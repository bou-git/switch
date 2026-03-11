const str = "Command failed: \"C:\\nssm\\nssm.exe\" start StrapiDevService\nS\u0000t\u0000r\u0000a\u0000p\u0000i\u0000D\u0000e\u0000v\u0000S\u0000e\u0000r\u0000v\u0000i\u0000c\u0000e\u0000:\u0000 \u0000S\u0000T\u0000A\u0000R\u0000T\u0000:\u0000 \u0000A\u0000n\u0000 \u0000i\u0000n\u0000s\u0000t\u0000a\u0000n\u0000c\u0000e\u0000 \u0000o\u0000f\u0000 \u0000t\u0000h\u0000e\u0000 \u0000s\u0000e\u0000r\u0000v\u0000i\u0000c\u0000e\u0000 \u0000i\u0000s\u0000 \u0000a\u0000l\u0000r\u0000e\u0000a\u0000d\u0000y\u0000 \u0000r\u0000u\u0000n\u0000n\u0000i\u0000n\u0000g\u0000.\u0000\r\u0000\r\u0000\n\u0000";

const cleanStr = str.replace(/\0/g, '');
console.log("Original:", JSON.stringify(str));
console.log("Clean:", JSON.stringify(cleanStr));
console.log("Includes:", cleanStr.includes("already running"));
console.log("Includes lower:", cleanStr.toLowerCase().includes("already running"));
console.log("Includes SERVICE:", cleanStr.includes("SERVICE_ALREADY_RUNNING"));
