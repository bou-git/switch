const axios = require("axios");

const CONFIG = {
  STRAPI_BASE_URL: "https://bouweb-test.bou.or.ug",
  AUDIT_LOG_ENDPOINT: "/api/audit-logs",
  STRAPI_API_TOKEN: "55b564dc5c9ad792170318288473e17dc0bb17fb1a7423374ab023a54126cde0a1bc2139f8127207c58a3f2b0d4a31aeaa69d4f570400c176dfcd556ed250427afdbdea0e49369998db965550e426e03db0cb54f35a588d61b2523886a3905f93b89684b4d64a68bcd077635fa2b4195dcedcac02d4f80c78221ee4a0679df0d"
};

async function testAudit() {
  console.log("Testing Strapi Audit Log Insertion...");
  try {
    const payload = {
      data: {
        action: "Test Developer Login",
        contentType: "Server Configuration",
        newData: { 
            info: `Triggered by test_script@bou.or.ug` 
        },
        actionTime: new Date().toISOString()
      }
    };
    
    console.log(`Sending POST request to ${CONFIG.STRAPI_BASE_URL}${CONFIG.AUDIT_LOG_ENDPOINT}...`);
    
    const res = await axios.post(`${CONFIG.STRAPI_BASE_URL}${CONFIG.AUDIT_LOG_ENDPOINT}`, payload, {
      headers: {
        Authorization: `Bearer ${CONFIG.STRAPI_API_TOKEN}`,
      },
    });
    
    console.log("✅ SUCCESS!");
    console.log("Response Status:", res.status);
    console.log("Strapi returned data ID:", res.data?.data?.id);
    console.log("Check your Strapi Admin Panel under 'Audit Logs' to verify!");
    
  } catch (error) {
    console.log("❌ FAILED!");
    if (error.response) {
      console.error("Status:", error.response.status);
      console.error("Error Data:", JSON.stringify(error.response.data, null, 2));
    } else {
      console.error("Message:", error.message);
    }
  }
}

testAudit();
