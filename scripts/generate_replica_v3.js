const fs = require('fs');
const cheerio = require('cheerio');
const path = require('path');

const contentPath = 'C:/Users/91730/.gemini/antigravity/brain/b0ddd3b0-1bec-4cd2-94e5-01b875bdd542/.system_generated/steps/914/content.md';
let raw = fs.readFileSync(contentPath, 'utf8');

const htmlStart = raw.indexOf('<!DOCTYPE html>');
if (htmlStart === -1) {
    console.error('Could not find <!DOCTYPE html> in content.md');
    process.exit(1);
}
let htmlStr = raw.substring(htmlStart);

const $ = cheerio.load(htmlStr);

// 1. Remove analytics and tracking
$('script[src*="intellimize"]').remove();
$('link[href*="intellimize"]').remove();
$('noscript:has(iframe[src*="googletagmanager"])').remove();

// 2. Remove all Cyera-specific massive data sections
// We want to keep the Nav, Hero, and Features (Bento Grid). Everything else goes.

// The mega menu contains tons of Cyera specific links. Let's empty the dropdowns or remove them.
$('.w-dropdown-list').remove(); // Kills the mega menus while keeping the top level nav

// We will find all sections. Usually Webflow uses <section> or div.section
const sections = $('section, .section, .section-padding');
sections.each((i, el) => {
    const text = $(el).text();
    // If a section contains case studies or integrations, delete it
    if (
        text.includes('Meet the Cyera customer') || 
        text.includes('Hear from security leaders') ||
        text.includes('Integrates seamlessly') ||
        text.includes('Book a Demo') || 
        text.includes('Get a demo') && i > 3 // late page CTAs
    ) {
        $(el).remove();
    }
});

// Remove the footer completely
$('footer').remove();
$('.footer').remove();

// Let's remove any "Cyera" logos or replace images
$('img').each((i, el) => {
    const src = $(el).attr('src') || '';
    if (src.includes('logo') || src.includes('cyera')) {
        // If it's the main navbar logo, just hide it or replace with text
        if ($(el).closest('.navbar').length) {
            $(el).replaceWith('<strong style="color:white; font-size: 24px; font-weight: bold; letter-spacing: -1px;">AGENTIC</strong>');
        }
    }
});

// 3. Deep Text Replacement on the remaining elements
function replaceText(node) {
    if (node.type === 'text') {
        let text = node.data;
        
        // Brand Name
        text = text.replace(/Cyera/gi, 'Hypher AI Gateway');
        
        // Hero
        text = text.replace(/AI-Native Data Security Platform/gi, 'Enterprise MCP Security Gateway');
        text = text.replace(/Discover, classify, govern, and protect sensitive data across cloud, SaaS, on-prem, and AI environments\./gi, 'Secure, govern, and audit your AI agents with enterprise-grade policy enforcement, DLP, and real-time threat detection for the Model Context Protocol.');
        
        // Bento
        text = text.replace(/Understand your data attack surface/gi, 'Secure your AI agent attack surface');
        text = text.replace(/Reduce the blast radius/gi, 'Enforce granular zero-trust policies');
        text = text.replace(/See where sensitive data is/gi, 'Monitor agent tool usage');
        text = text.replace(/know who can access it/gi, 'block unauthorized connections');
        text = text.replace(/and prevent breaches/gi, 'and prevent prompt injection');
        
        text = text.replace(/Data Security Posture Management/gi, 'Real-time Threat Shield');
        text = text.replace(/Data Privacy/gi, 'Agentic DLP & Redaction');
        text = text.replace(/Data Detection and Response/gi, 'UCP Connection Shield');
        text = text.replace(/Access Governance/gi, 'Hash-Chained Audit Logs');
        text = text.replace(/Data Discovery/gi, 'Granular Access Control');
        text = text.replace(/Data Classification/gi, 'Human-in-the-Loop (HITL)');
        text = text.replace(/Cloud Data Security/gi, 'Enterprise SSO & Auth');
        text = text.replace(/SaaS Data Security/gi, 'Per-agent Budget Control');
        text = text.replace(/On-Prem Data Security/gi, 'Geo-Blocking & Rate Limiting');
        text = text.replace(/AI Data Security/gi, 'SIEM & SOC2 Reporting');
        
        // Subtext
        text = text.replace(/The gateway discovers sensitive data across cloud, SaaS, on-prem, and AI environments/gi, 'The gateway inspects agent payloads across local tools, MCP servers, and cloud resources');
        text = text.replace(/so security teams can see where critical information lives and reduce blind spots in the data attack surface\./gi, 'so platform teams can enforce safety boundaries and prevent shadow AI execution.');
        text = text.replace(/The gateway classifies structured and unstructured data with AI-native and LLM-powered techniques/gi, 'The gateway redacts PII with real-time DLP techniques');
        text = text.replace(/to give teams clearer context around sensitive information and improve governance at scale\./gi, 'to give teams peace of mind when agents transmit data to external APIs.');
        text = text.replace(/The gateway provides data security posture management to help enterprises assess posture/gi, 'The gateway provides a unified threat shield to help enterprises block malicious prompts');
        text = text.replace(/understand exposure, and prioritize the most important data risks across distributed environments\./gi, 'understand agent behavior, and block unauthorized MCP tool calls.');

        node.data = text;
    } else if (node.type === 'tag' && node.name !== 'script' && node.name !== 'style') {
        for (const child of node.children) {
            replaceText(child);
        }
    }
}

$('body').each((i, el) => {
    replaceText(el);
});

// Fix links
$('a').each((i, el) => {
    let href = $(el).attr('href');
    if (href) {
        if (href.includes('demo') || href.includes('secure-the-unknown')) {
            $(el).attr('href', '/dashboard');
        } else if (href.includes('cyera.com')) {
            $(el).attr('href', '/');
        }
    }
});

// Title
$('title').text('Hypher AI Gateway | AI-Native Data Security');

const targetPath = 'c:/Users/91730/Downloads/Final Production/agentic - Copy/mcpsecurity-v3.3.0/src/landing/landing.html';
fs.writeFileSync(targetPath, $.html());
console.log('Successfully generated clean v3 replica landing page at ' + targetPath);
