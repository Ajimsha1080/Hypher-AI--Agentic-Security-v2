/*
MCP Security Gateway — Kubernetes Operator v3.0
Language: Go 1.22  |  Framework: controller-runtime

One-command deployment:
  kubectl apply -f deploy/install.yaml
  kubectl apply -f mcpgateway.yaml

MCPGateway CR example (mcpgateway.yaml):
  apiVersion: security.antigravity.dev/v1alpha1
  kind: MCPGateway
  metadata:
    name: acme-gateway
    namespace: ai-security
  spec:
    plan: enterprise
    replicas: 3
    host: ai-security.acme.com
    database:
      type: postgres
      host: my-rds.us-east-1.rds.amazonaws.com
      secretRef: mcpsg-db-secret
    redis:
      host: my-cache.elasticache.amazonaws.com
    tls:
      certManagerIssuer: letsencrypt-prod
    policies:
      failMode: fail_closed
      hitlApprovals: true
    secrets:
      jwtSecret: mcpsg-app-secret

Operator reconciles:
  1. ConfigMap  (env vars from spec)
  2. Migration Job (npm run db:migrate, pre-deploy)
  3. Deployment (rolling update, readiness gates)
  4. Service (ClusterIP)
  5. Ingress (nginx + cert-manager TLS)
  6. CronJobs (ML rebuild every 2h, HITL sweep every minute, retention daily)
  7. NetworkPolicy (zero-trust: only postgres/redis/443 egress)
*/
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/intstr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

// ── CRD TYPES ─────────────────────────────────────────────────────────

type MCPGateway struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              MCPGatewaySpec   `json:"spec,omitempty"`
	Status            MCPGatewayStatus `json:"status,omitempty"`
}

type MCPGatewaySpec struct {
	Plan     string `json:"plan"`           // cloud|starter|growth|team|enterprise
	Replicas int32  `json:"replicas,omitempty"` // default: 2
	Image    string `json:"image,omitempty"`

	Database DatabaseSpec `json:"database"`
	Redis    RedisSpec    `json:"redis"`
	TLS      TLSSpec      `json:"tls,omitempty"`
	Policies PolicySpec   `json:"policies,omitempty"`
	Secrets  SecretsSpec  `json:"secrets"`

	Host         string `json:"host,omitempty"`
	WildcardHost string `json:"wildcardHost,omitempty"`
	Monitoring   MonitoringSpec `json:"monitoring,omitempty"`
}

type DatabaseSpec struct {
	Host      string `json:"host"`
	Port      int32  `json:"port,omitempty"`
	Database  string `json:"database,omitempty"`
	Username  string `json:"username,omitempty"`
	SecretRef string `json:"secretRef"`
}

type RedisSpec struct {
	Host      string `json:"host"`
	Port      int32  `json:"port,omitempty"`
	SecretRef string `json:"secretRef,omitempty"`
}

type TLSSpec struct {
	CertManagerIssuer string `json:"certManagerIssuer,omitempty"`
	SecretName        string `json:"secretName,omitempty"`
}

type PolicySpec struct {
	FailMode      string `json:"failMode,omitempty"`
	HITLApprovals bool   `json:"hitlApprovals,omitempty"`
	DLPHipaaMode  bool   `json:"dlpHipaaMode,omitempty"`
}

type SecretsSpec struct {
	JWTSecret string `json:"jwtSecret"`
}

type MonitoringSpec struct {
	PrometheusEnabled bool `json:"prometheusEnabled,omitempty"`
}

type MCPGatewayStatus struct {
	Phase          string `json:"phase,omitempty"`
	ReadyReplicas  int32  `json:"readyReplicas,omitempty"`
	GatewayURL     string `json:"gatewayUrl,omitempty"`
	DashboardURL   string `json:"dashboardUrl,omitempty"`
	LastMigration  string `json:"lastMigration,omitempty"`
	LastReconciled string `json:"lastReconciled,omitempty"`
}

type MCPGatewayList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []MCPGateway `json:"items"`
}

func (m *MCPGateway) DeepCopyObject() runtime.Object     { out := *m; return &out }
func (m *MCPGatewayList) DeepCopyObject() runtime.Object { out := *m; return &out }

// ── RECONCILER ────────────────────────────────────────────────────────

type Reconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

func (r *Reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := ctrl.LoggerFrom(ctx)

	gw := &MCPGateway{}
	if err := r.Get(ctx, req.NamespacedName, gw); err != nil {
		if errors.IsNotFound(err) { return ctrl.Result{}, nil }
		return ctrl.Result{}, err
	}

	r.defaults(gw)

	steps := []struct {
		name string
		fn   func(context.Context, *MCPGateway) error
	}{
		{"configmap", r.configmap},
		{"migration", r.migration},
		{"deployment", r.deployment},
		{"service", r.service},
		{"ingress", r.ingress},
		{"cronjobs", r.cronjobs},
		{"networkpolicy", r.networkpolicy},
	}

	for _, step := range steps {
		if err := step.fn(ctx, gw); err != nil {
			log.Error(err, "Reconcile step failed", "step", step.name)
			gw.Status.Phase = "Failed"
			r.Status().Update(ctx, gw)
			return ctrl.Result{RequeueAfter: 30 * time.Second}, err
		}
	}

	gw.Status.Phase = "Running"
	gw.Status.LastReconciled = time.Now().UTC().Format(time.RFC3339)
	if gw.Spec.Host != "" {
		gw.Status.GatewayURL = "https://" + gw.Spec.Host + "/mcp"
		gw.Status.DashboardURL = "https://" + gw.Spec.Host + "/dashboard"
	}
	r.Status().Update(ctx, gw)

	log.Info("Reconciled MCPGateway", "name", req.Name, "gateway", gw.Status.GatewayURL)
	return ctrl.Result{RequeueAfter: 5 * time.Minute}, nil
}

func (r *Reconciler) defaults(gw *MCPGateway) {
	if gw.Spec.Replicas == 0     { gw.Spec.Replicas = 2 }
	if gw.Spec.Image == ""       { gw.Spec.Image = "ghcr.io/antigravity/mcp-security-gateway:3.0.0" }
	if gw.Spec.Database.Port == 0 { gw.Spec.Database.Port = 5432 }
	if gw.Spec.Redis.Port == 0   { gw.Spec.Redis.Port = 6379 }
	if gw.Spec.Database.Database == "" { gw.Spec.Database.Database = "mcp_security" }
	if gw.Spec.Database.Username == "" { gw.Spec.Database.Username = "mcp_admin" }
	if gw.Spec.Policies.FailMode == "" { gw.Spec.Policies.FailMode = "fail_closed" }
}

func (r *Reconciler) n(gw *MCPGateway) string { return "mcpsg-" + gw.Name }
func (r *Reconciler) l(gw *MCPGateway) map[string]string {
	return map[string]string{
		"app.kubernetes.io/name":     "mcp-security-gateway",
		"app.kubernetes.io/instance": gw.Name,
	}
}

func (r *Reconciler) envFrom(gw *MCPGateway) []corev1.EnvFromSource {
	return []corev1.EnvFromSource{
		{ConfigMapRef: &corev1.ConfigMapEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: r.n(gw) + "-config"}}},
		{SecretRef: &corev1.SecretEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: gw.Spec.Secrets.JWTSecret}}},
	}
}

// ── CONFIGMAP ─────────────────────────────────────────────────────────

func (r *Reconciler) configmap(ctx context.Context, gw *MCPGateway) error {
	data := map[string]string{
		"NODE_ENV": "production", "PORT": "3000", "LOG_LEVEL": "info",
		"FAIL_MODE": gw.Spec.Policies.FailMode, "ENABLE_DASHBOARD": "true",
		"MOCK_UPSTREAM": "false",
		"DATABASE_URL": fmt.Sprintf("postgresql://%s:$(POSTGRES_PASSWORD)@%s:%d/%s",
			gw.Spec.Database.Username, gw.Spec.Database.Host,
			gw.Spec.Database.Port, gw.Spec.Database.Database),
		"REDIS_URL": fmt.Sprintf("redis://%s:%d", gw.Spec.Redis.Host, gw.Spec.Redis.Port),
	}
	if gw.Spec.Policies.HITLApprovals { data["HITL_ENABLED"] = "true" }
	if gw.Spec.Policies.DLPHipaaMode  { data["DLP_HIPAA_MODE"] = "true" }

	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: r.n(gw)+"-config", Namespace: gw.Namespace, Labels: r.l(gw)}, Data: data}
	ctrl.SetControllerReference(gw, cm, r.Scheme)
	existing := &corev1.ConfigMap{}
	if errors.IsNotFound(r.Get(ctx, client.ObjectKey{Name: cm.Name, Namespace: cm.Namespace}, existing)) {
		return r.Create(ctx, cm)
	}
	existing.Data = data
	return r.Update(ctx, existing)
}

// ── MIGRATION JOB ─────────────────────────────────────────────────────

func (r *Reconciler) migration(ctx context.Context, gw *MCPGateway) error {
	name := fmt.Sprintf("%s-migrate-%d", r.n(gw), time.Now().Unix()/600)
	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: gw.Namespace, Labels: r.l(gw)},
		Spec: batchv1.JobSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
			RestartPolicy: corev1.RestartPolicyNever,
			Containers: []corev1.Container{{Name: "migrate", Image: gw.Spec.Image, Command: []string{"npm", "run", "db:migrate"}, EnvFrom: r.envFrom(gw)}},
		}}},
	}
	ctrl.SetControllerReference(gw, job, r.Scheme)
	existing := &batchv1.Job{}
	if errors.IsNotFound(r.Get(ctx, client.ObjectKey{Name: name, Namespace: gw.Namespace}, existing)) {
		if err := r.Create(ctx, job); err != nil { return err }
		gw.Status.LastMigration = time.Now().UTC().Format(time.RFC3339)
	}
	return nil
}

// ── DEPLOYMENT ────────────────────────────────────────────────────────

func (r *Reconciler) deployment(ctx context.Context, gw *MCPGateway) error {
	reps := gw.Spec.Replicas
	zero, one := intstr.FromInt(0), intstr.FromInt(1)
	t, f := true, false
	uid := int64(1000)
	deploy := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: r.n(gw), Namespace: gw.Namespace, Labels: r.l(gw)},
		Spec: appsv1.DeploymentSpec{
			Replicas: &reps, Selector: &metav1.LabelSelector{MatchLabels: r.l(gw)},
			Strategy: appsv1.DeploymentStrategy{Type: appsv1.RollingUpdateDeploymentStrategyType,
				RollingUpdate: &appsv1.RollingUpdateDeployment{MaxUnavailable: &zero, MaxSurge: &one}},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: r.l(gw)},
				Spec: corev1.PodSpec{
					SecurityContext: &corev1.PodSecurityContext{RunAsNonRoot: &t, RunAsUser: &uid, FSGroup: &uid},
					InitContainers: []corev1.Container{{
						Name: "wait-db", Image: "postgres:15-alpine",
						Command: []string{"sh", "-c", "until pg_isready -h " + gw.Spec.Database.Host + " -U " + gw.Spec.Database.Username + "; do sleep 2; done"},
					}},
					Containers: []corev1.Container{{
						Name: "gateway", Image: gw.Spec.Image,
						Ports:   []corev1.ContainerPort{{Name: "http", ContainerPort: 3000}},
						EnvFrom: r.envFrom(gw),
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("250m"), corev1.ResourceMemory: resource.MustParse("256Mi")},
							Limits:   corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("1000m"), corev1.ResourceMemory: resource.MustParse("512Mi")},
						},
						LivenessProbe:  &corev1.Probe{ProbeHandler: corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{Path: "/health/live", Port: intstr.FromInt(3000)}}, InitialDelaySeconds: 30, PeriodSeconds: 30},
						ReadinessProbe: &corev1.Probe{ProbeHandler: corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{Path: "/health/ready", Port: intstr.FromInt(3000)}}, InitialDelaySeconds: 10, PeriodSeconds: 10},
						SecurityContext: &corev1.SecurityContext{AllowPrivilegeEscalation: &f, ReadOnlyRootFilesystem: &t, Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}}},
						VolumeMounts: []corev1.VolumeMount{{Name: "tmp", MountPath: "/tmp"}},
					}},
					Volumes: []corev1.Volume{{Name: "tmp", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}}},
				},
			},
		},
	}
	ctrl.SetControllerReference(gw, deploy, r.Scheme)
	existing := &appsv1.Deployment{}
	if errors.IsNotFound(r.Get(ctx, client.ObjectKey{Name: deploy.Name, Namespace: deploy.Namespace}, existing)) {
		return r.Create(ctx, deploy)
	}
	existing.Spec.Replicas = &reps
	existing.Spec.Template.Spec.Containers[0].Image = gw.Spec.Image
	gw.Status.ReadyReplicas = existing.Status.ReadyReplicas
	return r.Update(ctx, existing)
}

// ── SERVICE ───────────────────────────────────────────────────────────

func (r *Reconciler) service(ctx context.Context, gw *MCPGateway) error {
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: r.n(gw), Namespace: gw.Namespace, Labels: r.l(gw)},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeClusterIP, Selector: r.l(gw),
			Ports: []corev1.ServicePort{{Name: "http", Port: 3000, TargetPort: intstr.FromString("http")}},
		},
	}
	ctrl.SetControllerReference(gw, svc, r.Scheme)
	existing := &corev1.Service{}
	if errors.IsNotFound(r.Get(ctx, client.ObjectKey{Name: svc.Name, Namespace: svc.Namespace}, existing)) {
		return r.Create(ctx, svc)
	}
	return nil
}

// ── INGRESS ───────────────────────────────────────────────────────────

func (r *Reconciler) ingress(ctx context.Context, gw *MCPGateway) error {
	if gw.Spec.Host == "" { return nil }
	pt := networkingv1.PathTypePrefix
	ic := "nginx"
	ing := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{Name: r.n(gw), Namespace: gw.Namespace, Labels: r.l(gw),
			Annotations: map[string]string{
				"cert-manager.io/cluster-issuer": gw.Spec.TLS.CertManagerIssuer,
				"nginx.ingress.kubernetes.io/proxy-read-timeout": "300",
			}},
		Spec: networkingv1.IngressSpec{IngressClassName: &ic,
			TLS: []networkingv1.IngressTLS{{Hosts: []string{gw.Spec.Host}, SecretName: r.n(gw)+"-tls"}},
			Rules: []networkingv1.IngressRule{{Host: gw.Spec.Host, IngressRuleValue: networkingv1.IngressRuleValue{HTTP: &networkingv1.HTTPIngressRuleValue{
				Paths: []networkingv1.HTTPIngressPath{{Path: "/", PathType: &pt, Backend: networkingv1.IngressBackend{Service: &networkingv1.IngressServiceBackend{
					Name: r.n(gw), Port: networkingv1.ServiceBackendPort{Number: 3000},
				}}}},
			}}}},
		},
	}
	ctrl.SetControllerReference(gw, ing, r.Scheme)
	existing := &networkingv1.Ingress{}
	if errors.IsNotFound(r.Get(ctx, client.ObjectKey{Name: ing.Name, Namespace: ing.Namespace}, existing)) {
		return r.Create(ctx, ing)
	}
	return nil
}

// ── CRON JOBS ─────────────────────────────────────────────────────────

func (r *Reconciler) cronjobs(ctx context.Context, gw *MCPGateway) error {
	for _, cron := range []struct{ name, sched string; cmd []string }{
		{r.n(gw)+"-ml",        "0 */2 * * *", []string{"node","dist/anomaly/rebuild-cron.js"}},
		{r.n(gw)+"-retention", "0 2 * * *",   []string{"node","dist/hitl/retention-cron.js"}},
		{r.n(gw)+"-hitl",      "* * * * *",   []string{"node","dist/hitl/timeout-sweep.js"}},
	} {
		cj := &batchv1.CronJob{
			ObjectMeta: metav1.ObjectMeta{Name: cron.name, Namespace: gw.Namespace, Labels: r.l(gw)},
			Spec: batchv1.CronJobSpec{Schedule: cron.sched, JobTemplate: batchv1.JobTemplateSpec{Spec: batchv1.JobSpec{
				Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
					RestartPolicy: corev1.RestartPolicyOnFailure,
					Containers: []corev1.Container{{Name: "cron", Image: gw.Spec.Image, Command: cron.cmd, EnvFrom: r.envFrom(gw)}},
				}},
			}}},
		}
		ctrl.SetControllerReference(gw, cj, r.Scheme)
		existing := &batchv1.CronJob{}
		if errors.IsNotFound(r.Get(ctx, client.ObjectKey{Name: cj.Name, Namespace: cj.Namespace}, existing)) {
			if err := r.Create(ctx, cj); err != nil { return err }
		}
	}
	return nil
}

// ── NETWORK POLICY ────────────────────────────────────────────────────

func (r *Reconciler) networkpolicy(ctx context.Context, gw *MCPGateway) error {
	tcp, udp := corev1.ProtocolTCP, corev1.ProtocolUDP
	p := func(n int) intstr.IntOrString { return intstr.FromInt(n) }
	np := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: r.n(gw), Namespace: gw.Namespace, Labels: r.l(gw)},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: r.l(gw)},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress},
			Ingress: []networkingv1.NetworkPolicyIngressRule{{Ports: []networkingv1.NetworkPolicyPort{{Protocol: &tcp, Port: func() *intstr.IntOrString { v := p(3000); return &v }()}}}},
			Egress: []networkingv1.NetworkPolicyEgressRule{
				{Ports: []networkingv1.NetworkPolicyPort{{Protocol: &udp, Port: func() *intstr.IntOrString { v := p(53);   return &v }()}}},
				{Ports: []networkingv1.NetworkPolicyPort{{Protocol: &tcp, Port: func() *intstr.IntOrString { v := p(5432); return &v }()}}},
				{Ports: []networkingv1.NetworkPolicyPort{{Protocol: &tcp, Port: func() *intstr.IntOrString { v := p(6379); return &v }()}}},
				{Ports: []networkingv1.NetworkPolicyPort{{Protocol: &tcp, Port: func() *intstr.IntOrString { v := p(443);  return &v }()}}},
			},
		},
	}
	ctrl.SetControllerReference(gw, np, r.Scheme)
	existing := &networkingv1.NetworkPolicy{}
	if errors.IsNotFound(r.Get(ctx, client.ObjectKey{Name: np.Name, Namespace: np.Namespace}, existing)) {
		return r.Create(ctx, np)
	}
	return nil
}

// ── SETUP & MAIN ──────────────────────────────────────────────────────

func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&MCPGateway{}).
		Owns(&appsv1.Deployment{}).Owns(&corev1.Service{}).
		Owns(&corev1.ConfigMap{}).Owns(&batchv1.CronJob{}).
		Owns(&networkingv1.NetworkPolicy{}).
		Complete(r)
}

func main() {
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&zap.Options{Development: os.Getenv("NODE_ENV") != "production"})))
	log := ctrl.Log.WithName("mcpsg-operator")

	scheme := runtime.NewScheme()
	scheme.AddKnownTypeWithName(schema.GroupVersionKind{Group:"security.antigravity.dev",Version:"v1alpha1",Kind:"MCPGateway"}, &MCPGateway{})
	scheme.AddKnownTypeWithName(schema.GroupVersionKind{Group:"security.antigravity.dev",Version:"v1alpha1",Kind:"MCPGatewayList"}, &MCPGatewayList{})

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme: scheme, LeaderElection: true,
		LeaderElectionID: "mcpsg-operator-leader",
		LeaderElectionNamespace: os.Getenv("OPERATOR_NAMESPACE"),
	})
	if err != nil { log.Error(err, "create manager"); os.Exit(1) }

	if err = (&Reconciler{Client: mgr.GetClient(), Scheme: mgr.GetScheme()}).SetupWithManager(mgr); err != nil {
		log.Error(err, "create controller"); os.Exit(1)
	}

	log.Info("MCP Security Gateway Kubernetes operator starting",
		"version", "3.0.0",
		"crd", "MCPGateway.security.antigravity.dev/v1alpha1",
	)
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		log.Error(err, "operator exited with error"); os.Exit(1)
	}
}
