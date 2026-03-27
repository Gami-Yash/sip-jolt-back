/**
 * SIPJOLT v1.00.0 Neural Core - SECURED AI Chat API
 * ================================================
 * Express router for /api/ai/chat
 * 
 * Backend handler with ROLE-BASED ACCESS CONTROL.
 * Enforces data segmentation and brand protection.
 */

import express from 'express';
import { GoogleGenerativeAI, HarmCategory, HarmBlockThreshold } from '@google/generative-ai';
import { buildContextualPrompt, ROLE_SPECIFIC_KNOWLEDGE } from '../../frontend/src/lib/knowledge_base.js';
import {
  SECURITY_SYSTEM_PROMPT,
  LANDLORD_SAFE_KNOWLEDGE,
  isQueryRestricted,
  isBrandQuery,
  getRestrictedResponse,
  getBrandResponse,
  logSecurityEvent,
} from '../../frontend/src/lib/security.js';
import { aiChatLimiter } from './middleware/rateLimiter.js';
import { ConversationAuditLogger } from './services/conversationAuditLogger.js';
import { requireAuth } from '../shared/middleware/rbac.js';

const router = express.Router();

const GEMINI_MODEL = 'gemini-1.5-pro';

const safetySettings = [
  {
    category: HarmCategory.HARM_CATEGORY_HARASSMENT,
    threshold: HarmBlockThreshold.BLOCK_MEDIUM_AND_ABOVE,
  },
  {
    category: HarmCategory.HARM_CATEGORY_HATE_SPEECH,
    threshold: HarmBlockThreshold.BLOCK_MEDIUM_AND_ABOVE,
  },
  {
    category: HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT,
    threshold: HarmBlockThreshold.BLOCK_MEDIUM_AND_ABOVE,
  },
  {
    category: HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT,
    threshold: HarmBlockThreshold.BLOCK_ONLY_HIGH,
  },
];

const generationConfig = {
  temperature: 0.3,
  topP: 0.8,
  topK: 40,
  maxOutputTokens: 2048,
};

function resolveUserRole(siteAssignments = []) {
  const roles = siteAssignments.map((assignment) => assignment.role);

  if (roles.includes('ops_admin') || roles.includes('ops_manager') || roles.includes('admin')) {
    return 'OPS_MANAGER';
  }

  if (roles.includes('technician') || roles.includes('partner') || roles.includes('partner_technician')) {
    return 'PARTNER_TECHNICIAN';
  }

  if (roles.includes('driver')) {
    return 'DRIVER';
  }

  if (roles.includes('building_manager') || roles.includes('landlord_viewer')) {
    return 'LANDLORD_VIEWER';
  }

  return 'UNKNOWN';
}

function buildSecureSystemPrompt(userRole) {
  const role = userRole;
  
  let systemPrompt = `
# SIPJOLT v1.00.0 SOVEREIGN ENFORCER - SECURED OPERATIONAL AI

${SECURITY_SYSTEM_PROMPT}

## CURRENT USER ROLE: ${role || 'UNKNOWN'}

`;

  if (role === 'LANDLORD_VIEWER') {
    systemPrompt += `
## AVAILABLE KNOWLEDGE (LANDLORD VIEW ONLY)
You have LIMITED knowledge access. Only answer questions covered below.
If asked about topics not covered here, say: "This information is restricted to operational staff."

${LANDLORD_SAFE_KNOWLEDGE}

## RESPONSE RULES FOR LANDLORD
- Keep responses focused on site status, delivery tracking, and maintenance schedules
- NEVER discuss ingredients, box contents, packing procedures, or operational details
- NEVER reveal supplier information, costs, or internal processes
- For ANY operational question: "Please contact your Operations representative."
`;
  } else if (role === 'DRIVER') {
    systemPrompt += `
## DRIVER OPERATIONAL KNOWLEDGE
You have access to delivery procedures, POD requirements, and GPS validation rules.
You do NOT have access to: pricing, costs, supplier information, or business data.

${buildContextualPrompt(undefined, role)}

## RESPONSE RULES FOR DRIVER
- Focus on delivery procedures, scanning, POD photos, GPS validation
- Enforce ZERO-WEIGHT RULE on every weight question
- NEVER discuss costs, pricing, suppliers, or margins
- For financial questions: "Please contact your dispatcher or Ops Manager."
`;
  } else if (role === 'PARTNER_TECHNICIAN') {
    systemPrompt += `
## PARTNER_TECHNICIAN OPERATIONAL KNOWLEDGE

${buildContextualPrompt(undefined, role)}

## RESPONSE RULES FOR PARTNER_TECHNICIAN
- Full access to operational procedures
- Guide through acceptance, refill, and SAFE_MODE recovery
- NEVER discuss costs, pricing, suppliers, or margins
- For business questions: "Please contact your Operations Manager."
`;
  } else if (role === 'OPS_MANAGER') {
    systemPrompt += `
## OPS_MANAGER FULL ACCESS

${buildContextualPrompt(undefined, role)}

## RESPONSE RULES FOR OPS_MANAGER
- Full access to all operational knowledge
- Can discuss packing, QC gates, incidents, user management
- Still enforce brand protection rules (SIPJOLT / Jolt Beverage Systems only)
- NEVER reveal third-party manufacturer or OEM information
`;
  } else {
    systemPrompt += `
## UNKNOWN ROLE - RESTRICTED ACCESS
User role not identified. Provide minimal assistance only.
Direct user to authenticate properly or contact support.
`;
  }

  systemPrompt += `

## BRAND PROTECTION (ALWAYS ENFORCE)
When asked who makes/manufactures/builds the machine, ALWAYS respond:
"The Jolt Automated Barista is designed and operated by SIPJOLT, a Jolt Beverage Systems company."

NEVER mention:
- OEMs or third-party manufacturers
- White-label arrangements
- External suppliers or partners
- Component sourcing details
`;

  return systemPrompt;
}

function buildEnrichedContext(context) {
  if (!context) return '';
  
  const parts = [];
  
  if (context.currentRoute) {
    parts.push(`**Current Screen:** ${context.currentRoute}`);
  }
  
  if (context.userRole) {
    parts.push(`**User Role:** \`${context.userRole}\``);
  }
  
  if (context.siteId) {
    parts.push(`**Site ID:** \`${context.siteId}\``);
  }
  
  if (context.siteStatus) {
    const statusEmoji = context.siteStatus === 'ACTIVE' ? '🟢' : 
                        context.siteStatus === 'SAFE_MODE' ? '🔴' : '⚫';
    parts.push(`**Site Status:** ${statusEmoji} ${context.siteStatus}`);
  }
  
  if (context.pendingTasks && context.pendingTasks.length > 0) {
    parts.push(`**Pending Tasks:** ${context.pendingTasks.join(', ')}`);
  }
  
  if (parts.length === 0) return '';
  
  return `
---
## SESSION CONTEXT
${parts.join('\n')}
---
`;
}

function formatConversationHistory(history) {
  if (!history || history.length === 0) return [];
  
  return history.map(msg => ({
    role: msg.role === 'assistant' ? 'model' : 'user',
    parts: [{ text: msg.content }],
  }));
}

router.post('/chat', requireAuth, aiChatLimiter, async (req, res) => {
  const timestamp = new Date().toISOString();
  const startTime = Date.now();
  
  try {
    const apiKey = process.env.GEMINI_API_KEY || process.env.GOOGLE_AI_API_KEY || process.env.AI_INTEGRATIONS_GOOGLE_AI_API_KEY;
    
    if (!apiKey) {
      console.error(`[${timestamp}] GOOGLE_AI_API_KEY not configured`);
      return res.status(500).json({
        success: false,
        error: 'AI service not configured. Contact Ops.',
        timestamp,
        model: GEMINI_MODEL,
      });
    }
    
    const genAI = new GoogleGenerativeAI(apiKey);
    const body = req.body;
    
    if (!body.message || typeof body.message !== 'string') {
      return res.status(400).json({
        success: false,
        error: 'Invalid request: message field required',
        timestamp,
        model: GEMINI_MODEL,
      });
    }
    
    const userMessage = body.message.trim().slice(0, 4000);
    
    if (userMessage.length === 0) {
      return res.status(400).json({
        success: false,
        error: 'Empty message not permitted',
        timestamp,
        model: GEMINI_MODEL,
      });
    }
    
    const userRole = resolveUserRole(req.siteAssignments);
    
    if (isBrandQuery(userMessage)) {
      logSecurityEvent(userRole, userMessage, true, 'BRAND_PROTECTION');
      
      return res.json({
        success: true,
        response: getBrandResponse(),
        timestamp,
        model: GEMINI_MODEL,
        restricted: true,
      });
    }
    
    if (isQueryRestricted(userMessage, userRole)) {
      logSecurityEvent(userRole, userMessage, true, 'TOPIC_RESTRICTED');
      
      return res.json({
        success: true,
        response: getRestrictedResponse(userRole),
        timestamp,
        model: GEMINI_MODEL,
        restricted: true,
      });
    }
    
    logSecurityEvent(userRole, userMessage, false);
    
    const systemPrompt = buildSecureSystemPrompt(userRole);
    const contextPayload = {
      ...body.context,
      userRole,
    };
    const contextBlock = buildEnrichedContext(contextPayload);
    
    const model = genAI.getGenerativeModel({
      model: GEMINI_MODEL,
      systemInstruction: systemPrompt,
      safetySettings,
      generationConfig,
    });
    
    const chat = model.startChat({
      history: formatConversationHistory(body.conversationHistory),
    });
    
    const enrichedMessage = contextBlock 
      ? `${contextBlock}\n\n**User Query:** ${userMessage}`
      : userMessage;
    
    console.log(`[${timestamp}] [SECURED] Processing - Role: ${userRole}, Route: ${body.context?.currentRoute || 'UNKNOWN'}`);
    
    const result = await chat.sendMessage(enrichedMessage);
    const response = result.response;
    let responseText = response.text();
    
    if (userRole === 'LANDLORD_VIEWER') {
      const restrictedPatterns = [
        /matcha/gi,
        /oat powder/gi,
        /dairy powder/gi,
        /syrup jug/gi,
        /oxygen absorber/gi,
        /hdx.*rack/gi,
        /qc gate/gi,
        /shake test/gi,
        /box [abcde]/gi,
        /zone [abcde]/gi,
        /supplier/gi,
        /vendor/gi,
        /\$\d+/g,
      ];
      
      let containsRestricted = false;
      for (const pattern of restrictedPatterns) {
        if (pattern.test(responseText)) {
          containsRestricted = true;
          break;
        }
      }
      
      if (containsRestricted) {
        console.warn(`[${timestamp}] [SECURITY] Output contained restricted content for LANDLORD - sanitizing`);
        responseText = 'This information is restricted to operational staff. Please contact your Operations representative for assistance.';
      }
    }
    
    console.log(`[${timestamp}] [SECURED] Response generated - Length: ${responseText.length} chars`);
    
    return res.json({
      success: true,
      response: responseText,
      timestamp,
      model: GEMINI_MODEL,
    });
    
  } catch (error) {
    console.error(`[${timestamp}] Neural Core Error:`, error);
    
    if (error.message) {
      if (error.message.includes('429') || error.message.includes('quota')) {
        return res.status(429).json({
          success: false,
          error: 'AI service temporarily unavailable. Please try again in a moment.',
          timestamp,
          model: GEMINI_MODEL,
        });
      }
      
      if (error.message.includes('401') || error.message.includes('API key')) {
        return res.status(500).json({
          success: false,
          error: 'AI service authentication failed. Contact Ops.',
          timestamp,
          model: GEMINI_MODEL,
        });
      }
      
      if (error.message.includes('SAFETY') || error.message.includes('blocked')) {
        return res.status(400).json({
          success: false,
          error: 'Query blocked by safety filters. Rephrase your question.',
          timestamp,
          model: GEMINI_MODEL,
        });
      }
    }
    
    return res.status(500).json({
      success: false,
      error: 'Failed to process request. Please try again.',
      timestamp,
      model: GEMINI_MODEL,
    });
  }
});

router.get('/status', (req, res) => {
  const timestamp = new Date().toISOString();
  
  return res.json({
    status: 'operational',
    service: 'SIPJOLT v1.00 Neural Core - SECURED',
    model: GEMINI_MODEL,
    timestamp,
    features: [
      'Context-aware responses',
      'Role-based knowledge injection',
      'SAFE_MODE guidance',
      '2-Point Recovery walkthrough',
      'Zero-Weight Rule enforcement',
      'Brand protection',
      'Data segmentation by role',
      'Output sanitization for LANDLORD_VIEWER',
    ],
  });
});

router.get('/time', (req, res) => {
  const now = new Date();
  return res.json({
    success: true,
    serverTime: now.toISOString(),
    timestamp: now.getTime(),
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
  });
});

export default router;
