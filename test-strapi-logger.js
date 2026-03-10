"use strict";

/**
 * STANDALONE TEST SCRIPT FOR STRAPI LOGGER
 * 
 * This script allows you to test the log submission to Strapi
 * without modifying the main index.js file.
 * 
 * Usage: node test-strapi-logger.js
 */

const { logAuditToStrapi } = require("./strapi-logger");

// --- CONFIGURATION (Mirrored from index.js) ---
const CONFIG = {
  STRAPI_BASE_URL: "https://bouweb-test.bou.or.ug",
  AUDIT_LOG_ENDPOINT: "/api/audit-logs",
  STRAPI_API_TOKEN: "55b564dc5c9ad792170318288473e17dc0bb17fb1a7423374ab023a54126cde0a1bc2139f8127207c58a3f2b0d4a31aeaa69d4f570400c176dfcd556ed250427afdbdea0e49369998db965550e426e03db0cb54f35a588d61b2523886a3905f93b89684b4d64a68bcd077635fa2b4195dcedcac02d4f80c78221ee4a0679df0d",
};

// --- MOCK LOCAL LOGGER ---
const mockWriteLog = (msg) => {
  console.log(`[LOCAL LOG] ${msg}`);
};

async function runTest() {
  console.log("--- Starting Strapi Logger Test ---");

  const testAction = "Standalone Logger Test Execution";
  const testUserEmail = "test-user@bou.or.ug";
  const testUserId = 1; // Example user ID

  try {
    console.log(`Sending log: "${testAction}" for user ${testUserEmail}...`);

    await logAuditToStrapi(
      testAction,
      testUserEmail,
      testUserId,
      CONFIG,
      mockWriteLog
    );

    console.log("\n--- Test Completed Successfully ---");
    console.log("Check the Strapi Admin Panel -> Audit Logs to verify.");
  } catch (error) {
    console.error("\n--- Test Failed ---");
    // Detailed error logging is already handled inside logAuditToStrapi
  }
}

runTest();
