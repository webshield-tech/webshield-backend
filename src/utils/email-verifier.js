import axios from "axios";
import dotenv from "dotenv";

dotenv.config();
export const verifyEmailExistence = async (email) => {
  try {
    const apiKey = process.env.ABSTRACT_API_KEY;

    if (!apiKey) {
      console.warn("ABSTRACT_API_KEY not set, using basic validation");
      return basicEmailCheck(email);
    }

    const response = await axios.get(
      "https://emailvalidation.abstractapi.com/v1/",
      {
        params: {
          api_key: apiKey,
          email: email,
        },
      },
    );

    const data = response.data;
    console.log("Email verification result:", {
      email,
      valid: data.is_valid_format?.value,
      deliverable: data.deliverability,
      disposable: data.is_disposable_email?.value,
      roleEmail: data.is_role_email?.value,
    });

    // Strict validation: Must be valid format AND deliverable AND not disposable
    const isValid =
      data.is_valid_format?.value === true &&
      data.deliverability === "DELIVERABLE" &&
      data.is_disposable_email?.value === false &&
      data.is_role_email?.value === false;

    return isValid;
  } catch (error) {
    console.error("Email verification API error:", error.message);
    // Fallback to basic validation if API fails
    return basicEmailCheck(email);
  }
};

// Fallback function for when API fails
const basicEmailCheck = (email) => {
  const [localPart, domain] = email.toLowerCase().split("@");

  const disposableDomains = [
    "tempmail.com",
    "10minutemail.com",
    "mailinator.com",
    "guerrillamail.com",
    "yopmail.com",
    "trashmail.com",
    "sharklasers.com",
    "grr.la",
    "maildrop.cc",
  ];

  // Block disposable domains
  if (disposableDomains.includes(domain)) {
    return false;
  }

  // Block obviously fake emails
  if (/^\d+$/.test(localPart)) return false; 
  if (/^(test|demo|fake|dummy|admin|user)/.test(localPart)) return false;
  if (localPart.length < 2) return false;

  return true;
};
