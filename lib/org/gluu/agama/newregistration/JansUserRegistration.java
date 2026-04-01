package org.gluu.agama.newregistration;

import io.jans.as.common.model.common.User;
import io.jans.as.common.service.common.EncryptionService;
import io.jans.as.common.service.common.UserService;
import io.jans.orm.model.base.CustomObjectAttribute;
import io.jans.orm.exception.operation.EntryNotFoundException;
import io.jans.service.MailService;
import io.jans.model.SmtpConfiguration;
import io.jans.service.cdi.util.CdiUtil;
import io.jans.util.StringHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.URI;

import org.gluu.agama.newuser.NewUserRegistration;
import io.jans.agama.engine.script.LogUtils;
import java.io.IOException;
import io.jans.as.common.service.common.ConfigurationService;
import java.security.SecureRandom;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.regex.Pattern;

// import org.gluu.agama.EmailTemplate;
// import org.gluu.agama.registration.Labels;
import org.gluu.agama.smtp.*;

import com.twilio.Twilio;
import com.twilio.rest.api.v2010.account.Message;
import com.twilio.type.PhoneNumber;



public class JansUserRegistration extends NewUserRegistration {

    private static final Logger logger = LoggerFactory.getLogger(JansUserRegistration.class);
    
    private static final String SN = "sn";
    private static final String CONFIRM_PASSWORD = "confirmPassword";
    private static final String LANG = "lang";
    private static final String REFERRAL_CODE = "referralCode";
    private static final String RESIDENCE_COUNTRY = "residenceCountry";
    private static final String PHONE_NUMBER = "mobile";
    private static final String MAIL = "mail";
    private static final String UID = "uid";
    private static final String DISPLAY_NAME = "displayName";
    private static final String GIVEN_NAME = "givenName";
    private static final String PASSWORD = "userPassword";
    private static final String INUM_ATTR = "inum";
    private static final String EXT_ATTR = "jansExtUid";
    private static final String USER_STATUS = "jansStatus";
    private static final String EXT_UID_PREFIX = "github:";
    private static final String EMAIL_VERIFIED = "emailVerified";
    private static final String PHONE_VERIFIED = "phoneNumberVerified";
    private static final int OTP_LENGTH = 6;
    public static final int OTP_CODE_LENGTH = 6;
    private static final String SUBJECT_TEMPLATE = "Here's your verification code: %s";
    private static final String MSG_TEMPLATE_TEXT = "%s is the code to complete your verification";   
    private static final SecureRandom RAND = new SecureRandom();
    

    private static JansUserRegistration INSTANCE = null;
    private Map<String, String> flowConfig;
    private final Map<String, String> emailOtpStore = new HashMap<>();
    private static final Map<String, String> userCodes = new HashMap<>();

    //  No-arg constructor
    public JansUserRegistration() {
        this.flowConfig = new HashMap<>();
        logger.info("Initialized JansUserRegistration using default constructor (no config).");
    }

    //  Constructor used by config
    private JansUserRegistration(Map<String, String> config) {
        this.flowConfig = config;
        logger.info("Using Twilio account SID: {}", config.get("ACCOUNT_SID"));
    }

    //  No-arg singleton accessor (required by engine)
    public static synchronized NewUserRegistration getInstance() {
        if (INSTANCE == null) {
            Map<String, String> config = loadTwilioConfig();
            INSTANCE = new JansUserRegistration(config);
        }
        return INSTANCE;
    }

    //  Config-based singleton accessor
    public static synchronized NewUserRegistration getInstance(Map<String, String> config) {
        if (INSTANCE == null) {
            INSTANCE = new JansUserRegistration(config);
        }
        return INSTANCE;
    }

    public  Map<String, Object> validateInputs(Map<String, String> profile) {
        LogUtils.log("Validate inputs ");
        Map<String, Object> result = new HashMap<>();

        if (profile.get(UID)== null || !Pattern.matches('''^[A-Za-z][A-Za-z0-9]{5,19}$''', profile.get(UID))) {
            result.put("valid", false);
            result.put("message", "Invalid username. Must be 6-20 characters, start with a letter, and contain only letters, digits");
            return result;
        }
        if (profile.get(PASSWORD)==null || !Pattern.matches('''^(?=.*[A-Za-z])(?=.*\\d)(?=.*[!"#$%&'()*+,-./:;<=>?@[\\\\]^_`{|}~])[!-~&&[^ ]]{12,24}$''', profile.get(PASSWORD))) {
            result.put("valid", false);
            result.put("message", "Invalid password. Must be at least 12 to 24 characters with uppercase, lowercase, digit, and special character.");
            return result;
        }

        if (profile.get(LANG) == null || !Pattern.matches('''^(ar|en|es|fr|pt|id)$''', profile.get(LANG))) {
            result.put("valid", false);
            result.put("message", "Invalid language code. Must be one of ar, en, es, fr, pt, or id.");
            return result;
        }

        if (profile.get(RESIDENCE_COUNTRY) == null || !Pattern.matches('''^[A-Z]{2}$''', profile.get(RESIDENCE_COUNTRY))) {
            result.put("valid", false);
            result.put("message", "Invalid residence country. Must be exactly two uppercase letters.");
            return result;
        }

        if (!profile.get(PASSWORD).equals(profile.get(CONFIRM_PASSWORD))) {
            result.put("valid", false);
            result.put("message", "Password and confirm password do not match");
            return result;
        }

        result.put("valid", true);
        result.put("message", "All inputs are valid.");
        return result;
    }      

    public Map<String, String> getUserEntityByMail(String email) {
        User user = getUser(MAIL, email);
        boolean local = user != null;
        LogUtils.log("There is % local account for %", local ? "a" : "no", email);
    
        if (local) {            
            String uid = getSingleValuedAttr(user, UID);
            String inum = getSingleValuedAttr(user, INUM_ATTR);
            String name = getSingleValuedAttr(user, GIVEN_NAME);
    
            if (name == null) {
                name = getSingleValuedAttr(user, DISPLAY_NAME);
                if (name == null && email != null && email.contains("@")) {
                    name = email.substring(0, email.indexOf("@"));
                }
            }
    
            // Creating a truly modifiable map
            Map<String, String> userMap = new HashMap<>();
            userMap.put(UID, uid);
            userMap.put(INUM_ATTR, inum);
            userMap.put("name", name);
            userMap.put("email", email);
    
            return userMap;
        }
    
        return new HashMap<>();
    }
    

    public Map<String, String> getUserEntityByUsername(String username) {
        User user = getUser(UID, username);
        boolean local = user != null;
        LogUtils.log("There is % local account for %", local ? "a" : "no", username);
    
        if (local) {
            String email = getSingleValuedAttr(user, MAIL);
            String inum = getSingleValuedAttr(user, INUM_ATTR);
            String name = getSingleValuedAttr(user, GIVEN_NAME);
            String uid = getSingleValuedAttr(user, UID); // Define uid properly
    
            if (name == null) {
                name = getSingleValuedAttr(user, DISPLAY_NAME);
                if (name == null && email != null && email.contains("@")) {
                    name = email.substring(0, email.indexOf("@"));
                }
            }    
            // Creating a modifiable HashMap directly
            Map<String, String> userMap = new HashMap<>();
            userMap.put(UID, uid);
            userMap.put(INUM_ATTR, inum);
            userMap.put("name", name);
            userMap.put("email", email);
    
            return userMap;
        }
    
        return new HashMap<>();
    }

    public String sendEmail(String to, String lang) {
        try {
            ConfigurationService configService = CdiUtil.bean(ConfigurationService.class);
            SmtpConfiguration smtpConfig = configService.getConfiguration().getSmtpConfiguration();

            if (smtpConfig == null) {
                LogUtils.log("SMTP configuration is missing.");
                return null;
            }

            // Preferred language or fallback to English
            String preferredLang = (lang != null && !lang.isEmpty())
                    ? lang.toLowerCase()
                    : "en";

            // Generate OTP
            String otp = IntStream.range(0, OTP_LENGTH)
                    .mapToObj(i -> String.valueOf(RAND.nextInt(10)))
                    .collect(Collectors.joining());

            // Pick localized email template
            Map<String, String> templateData;
            switch (preferredLang) {
                case "ar":
                    templateData = EmailRegistrationOtpAr.get(otp);
                    break;
                case "es":
                    templateData = EmailRegistrationOtpEs.get(otp);
                    break;
                case "fr":
                    templateData = EmailRegistrationOtpFr.get(otp);
                    break;
                case "id":
                    templateData = EmailRegistrationOtpId.get(otp);
                    break;
                case "pt":
                    templateData = EmailRegistrationOtpPt.get(otp);
                    break;
                default:
                    templateData = EmailRegistrationOtpEn.get(otp);
                    break;
            }

            String subject = templateData.get("subject");
            String htmlBody = templateData.get("body");
            String textBody = htmlBody.replaceAll("\\<.*?\\>", ""); // crude strip HTML

            // Send email
            MailService mailService = CdiUtil.bean(MailService.class);
            boolean sent = mailService.sendMailSigned(
                    smtpConfig.getFromEmailAddress(),
                    smtpConfig.getFromName(),
                    to,
                    null,
                    subject,
                    textBody,
                    htmlBody);

            if (sent) {
                LogUtils.log("Localized registration OTP email sent to %", to);
                return otp; // return OTP so you can validate later
            } else {
                LogUtils.log("Failed to send registration OTP email to %", to);
                return null;
            }

        } catch (Exception e) {
            LogUtils.log("Failed to send registration OTP email: %", e.getMessage());
            return null;
        }
    }



    private SmtpConfiguration getSmtpConfiguration() {
        ConfigurationService configurationService = CdiUtil.bean(ConfigurationService.class);
        SmtpConfiguration smtpConfiguration = configurationService.getConfiguration().getSmtpConfiguration();
        return smtpConfiguration;

    }
    
        
    public String sendOTPCode(String phone, String lang) {
        try {
            logger.info("Sending OTP Code via SMS to phone: {}", phone);

            String otpCode = generateSMSOTpCode(OTP_CODE_LENGTH);
            logger.info("Generated OTP {} for phone {}", otpCode, phone);

            
            String preferredLang = (lang != null && !lang.isEmpty()) ? lang.toLowerCase() : "en";

            Map<String, String> messages = new HashMap<>();

            messages.put("ar", "رمز التحقق OTP الخاص بك من Phi Wallet هو " + otpCode + ". لا تشاركه مع أي شخص.");
            messages.put("en", "Your Phi Wallet OTP is " + otpCode + ". Do not share it with anyone.");
            messages.put("es", "Tu código de Phi Wallet es " + otpCode + ". No lo compartas con nadie.");
            messages.put("fr", "Votre code Phi Wallet est " + otpCode + ". Ne le partagez avec personne.");
            messages.put("id", "Kode Phi Wallet Anda adalah " + otpCode + ". Jangan bagikan kepada siapa pun.");
            messages.put("pt", "O seu código da Phi Wallet é " + otpCode + ". Não o partilhe com ninguém.");

            String message = messages.getOrDefault(preferredLang, messages.get("en"));

            associateGeneratedCodeToPhone(phone, otpCode);

            sendTwilioSms(phone, message);

            return phone;
        } catch (Exception ex) {
            logger.error("Failed to send OTP to phone: {}. Error: {}", phone, ex.getMessage(), ex);
            return null;
        }
    }


    private String generateSMSOTpCode(int codeLength) {
        String numbers = "0123456789";
        SecureRandom random = new SecureRandom();
        char[] otp = new char[codeLength];
        for (int i = 0; i < codeLength; i++) {
            otp[i] = numbers.charAt(random.nextInt(numbers.length()));
        }
        return new String(otp);
    }

    private boolean associateGeneratedCodeToPhone(String phone, String code) {
        try {
            logger.info("Associating code {} to phone {}", code, phone);
            userCodes.put(phone, code);
            logger.info("userCodes map now: {}", userCodes);
            return true;
        } catch (Exception e) {
            logger.error("Error associating OTP code to phone {}. Error: {}", phone, e.getMessage(), e);
            return false;
        }
    }

    private boolean sendTwilioSms(String phone, String message) {
        try {
            // Determine which FROM_NUMBER to use based on country code
            String fromNumber = getFromNumberForPhone(phone);
            
            if (fromNumber == null || fromNumber.trim().isEmpty()) {
                logger.error("FROM_NUMBER is null or empty, cannot send OTP to {}", phone);
                return false;
            }

            PhoneNumber FROM_NUMBER = new com.twilio.type.PhoneNumber(fromNumber);

            logger.info("Sending from: {}", fromNumber);

            PhoneNumber TO_NUMBER = new com.twilio.type.PhoneNumber(phone);

            logger.info("Sending to: {}", phone);

            Twilio.init(flowConfig.get("ACCOUNT_SID"), flowConfig.get("AUTH_TOKEN"));

            Message.creator(TO_NUMBER, FROM_NUMBER, message).create();

            logger.info("OTP code has been successfully sent to {}", phone);

            return true;
        } catch (Exception exception) {
            logger.error("Error sending OTP code to {}: {}", phone, exception.getMessage(), exception);
            return false;
        }
    }

    /**
     * Determines which FROM_NUMBER to use based on the phone number's country code.
     * Priority: 1) US/Canada (+1) → FROM_NUMBER_US
     *           2) Restricted countries → FROM_NUMBER_RESTRICTED_COUNTRIES  
     *           3) All others use default FROM_NUMBER.
     */
    private String getFromNumberForPhone(String phone) {
        try {
            String defaultFromNumber = flowConfig.get("FROM_NUMBER");
            String usCountryCodes = flowConfig.get("US_COUNTRY_CODES");
            String restrictedCodes = flowConfig.get("RESTRICTED_COUNTRY_CODES");
            
            if (defaultFromNumber == null || defaultFromNumber.trim().isEmpty()) {
                logger.error("FROM_NUMBER not configured");
                return null;
            }
            
            // Parse US country codes for matching
            Set<String> usCountrySet = new HashSet<>();
            if (usCountryCodes != null && !usCountryCodes.trim().isEmpty()) {
                usCountrySet = Arrays.stream(usCountryCodes.split(","))
                        .map(String::trim)
                        .filter(s -> !s.isEmpty())
                        .collect(Collectors.toSet());
            }
            
            // Parse restricted country codes for matching
            Set<String> restrictedSet = new HashSet<>();
            if (restrictedCodes != null && !restrictedCodes.trim().isEmpty()) {
                restrictedSet = Arrays.stream(restrictedCodes.split(","))
                        .map(String::trim)
                        .filter(s -> !s.isEmpty())
                        .collect(Collectors.toSet());
            }
            
            // Combine both sets for accurate country code extraction
            Set<String> allKnownCodes = new HashSet<>();
            allKnownCodes.addAll(usCountrySet);
            allKnownCodes.addAll(restrictedSet);
            
            // Extract country code from phone number
            String countryCode = extractCountryCode(phone, allKnownCodes);
            
            if (countryCode == null || countryCode.isEmpty()) {
                return defaultFromNumber;
            }

            // Priority 1: Check if country code is in US_COUNTRY_CODES - use US-specific sender
            if (usCountrySet.contains(countryCode)) {
                String usFromNumber = flowConfig.get("FROM_NUMBER_US");
                
                if (usFromNumber != null && !usFromNumber.trim().isEmpty()) {
                    logger.info("Using US-specific sender {} for country code {}", usFromNumber, countryCode);
                    return usFromNumber;
                }
            }

            // Priority 2: Check if country code is in restricted list
            if (restrictedSet.contains(countryCode)) {
                String restrictedFromNumber = flowConfig.get("FROM_NUMBER_RESTRICTED_COUNTRIES");
                
                if (restrictedFromNumber != null && !restrictedFromNumber.trim().isEmpty()) {
                    logger.info("Using restricted sender {} for country code {}", restrictedFromNumber, countryCode);
                    return restrictedFromNumber;
                }
            }

            return defaultFromNumber;
        } catch (Exception ex) {
            logger.error("Error in getFromNumberForPhone: {}", ex.getMessage(), ex);
            return flowConfig.get("FROM_NUMBER");
        }
    }

    /**
     * Extract country code from phone number by matching against known codes.
     * Returns 1-digit code "1" or 2-3 digit country code.
     */
    private String extractCountryCode(String phone, Set<String> knownCodes) {
        if (phone == null || phone.trim().isEmpty()) {
            return null;
        }

        String cleaned = phone.startsWith("+") ? phone.substring(1) : phone;
        
        if (cleaned.length() < 2) {
            return null;
        }

        // Handle code "1" first (US/Canada and territories)
        if (cleaned.startsWith("1") && cleaned.length() > 1 && Character.isDigit(cleaned.charAt(1))) {
            return "1";
        }
        
        // Try 3-digit codes ONLY if they're in our knownCodes list
        if (cleaned.length() >= 3 && knownCodes != null && !knownCodes.isEmpty()) {
            String threeDigit = cleaned.substring(0, 3);
            if (knownCodes.contains(threeDigit)) {
                return threeDigit;
            }
        }
        
        // Default: Extract 2-digit country code
        return cleaned.substring(0, 2);
    }

    public boolean validateOTPCode(String phone, String code) {
        try {
            logger.info("Validating OTP code {} for phone {}", code, phone);
            String storedCode = userCodes.getOrDefault(phone, "NULL");
            logger.info("User submitted code: {} — Stored code: {}", code, storedCode);
            if (storedCode.equalsIgnoreCase(code)) {
                userCodes.remove(phone); // Remove after successful validation
                return true;
            }
            return false;
        } catch (Exception ex) {
            logger.error("Error validating OTP code {} for phone {}. Error: {}", code, phone, ex.getMessage(), ex);
            return false;
        }
    }




    public String addNewUser(Map<String, String> profile) throws Exception {
        Set<String> attributes = Set.of("uid", "mail", "displayName","givenName", "sn", "userPassword", "lang", "residenceCountry", "referralCode");
        User user = new User();
    
        attributes.forEach(attr -> {
            String val = profile.get(attr);
            if (StringHelper.isNotEmpty(val)) {
                user.setAttribute(attr, val);      
            }
        });

        // defaults
        user.setAttribute("emailVerified", Boolean.TRUE);
        user.setAttribute("phoneNumberVerified", Boolean.FALSE);

        UserService userService = CdiUtil.bean(UserService.class);
        user = userService.addUser(user, true); // Set user status active
    
        if (user == null) {
            throw new EntryNotFoundException("Added user not found");
        }
    
        return getSingleValuedAttr(user, INUM_ATTR);
    } 

    public String markPhoneAsVerified(String userName, String phone) {
        try {
            UserService userService = CdiUtil.bean(UserService.class);
            User user = getUser(UID, userName);
            if (user == null) {
                logger.error("User not found for username {}", userName);
                return "User not found.";
            }

            // Just set to true
            user.setAttribute(PHONE_NUMBER, phone);
            user.setAttribute(PHONE_VERIFIED, Boolean.TRUE);
            
            userService.updateUser(user);
            logger.info("Phone verification set to TRUE for UID {}", userName);
            return "Phone " + phone + " verified successfully for user " + userName;
        } catch (Exception e) {
            logger.error("Error setting phone verified TRUE for UID {}: {}", userName, e.getMessage(), e);
            return "Error: " + e.getMessage();
        }
    }

    private String getCustomAttribute(User user, String attributeName) {
        UserService userService = CdiUtil.bean(UserService.class);

        CustomObjectAttribute customAttribute = userService.getCustomAttribute(user, attributeName);

        if (customAttribute != null) {
            return customAttribute.getValue();
        }

        return null;
    }


    public boolean isPhoneUnique(String username, String phone) {
        try {
            logger.info("=== isPhoneUnique() called for user: {}, phone: {} ===", username, phone);

            UserService userService = CdiUtil.bean(UserService.class);
            if (userService == null) {
                logger.error("UserService is NULL in isPhoneUnique()");
                return false;
            }

            String normalizedPhone = phone.startsWith("+") ? phone : "+" + phone;
            logger.info("Normalized phone: {}", normalizedPhone);

            List<User> users = userService.getUsersByAttribute("mobile", normalizedPhone, true, 10);
            logger.info("LDAP search result size: {}", users != null ? users.size() : "NULL");

            if (users != null && !users.isEmpty()) {

                for (User u : users) {

                    if (u.getUserId().equalsIgnoreCase(username)) {
                        continue;
                    }

                    // User fullUser = userService.getUserByAttribute("uid", u.getUserId(), true);

                    User fullUser = userService.getUser(u.getUserId(), "uid", "jansStatus");

                    logger.info("Direct getStatus() = {}", fullUser.getStatus());
                    logger.info("getAttribute jansStatus = {}", fullUser.getAttribute("jansStatus", true, false));
                    logger.info("getCustomAttribute jansStatus = {}", 
                        userService.getCustomAttribute(fullUser, "jansStatus") != null 
                            ? userService.getCustomAttribute(fullUser, "jansStatus").getValue() 
                            : "NULL");

                    String status = getSingleValuedAttr(fullUser, "jansStatus");

                    logger.info("Found user {} with jansStatus {}", fullUser.getUserId(), status);

                    if (status == null || "active".equalsIgnoreCase(status)) {

                        logger.info("Phone {} already used by ACTIVE user {}", phone, u.getUserId());
                        return false;

                    }
                }
            }

            logger.info("Phone {} allowed (either not exists or user inactive)", phone);
            return true;

        } catch (Exception e) {
            logger.error("Error checking phone uniqueness for {}: {}", phone, e.getMessage(), e);
            return false;
        }
    }

    // private String getSingleValuedAttr(User user, String attribute) {
    //     Object value = null;
    //     if (attribute.equals(UID)) {
    //         //user.getAttribute("uid", true, false) always returns null :(
    //         value = user.getUserId();
    //     } else {
    //         value = user.getAttribute(attribute, true, false);
    //     }
    //     return value == null ? null : value.toString();

    // }

    private String getSingleValuedAttr(User user, String attribute) {
        Object value = null;

        if (attribute.equals(UID)) {
            value = user.getUserId();
        } else if (attribute.equals("jansStatus")) {
            // jansStatus is a first-class field on User — read it directly
            value = user.getStatus() != null ? user.getStatus().getValue() : null;
        } else {
            value = user.getAttribute(attribute, true, false);
        }

        // Final fallback: try custom attribute path
        if (value == null) {
            UserService userService = CdiUtil.bean(UserService.class);
            CustomObjectAttribute customAttr = userService.getCustomAttribute(user, attribute);
            if (customAttr != null) {
                value = customAttr.getValue();
            }
        }

        return value == null ? null : value.toString();
    }

    private static User getUser(String attributeName, String value) {
        UserService userService = CdiUtil.bean(UserService.class);
        return userService.getUserByAttribute(attributeName, value, true);
    }  
    
    public static Map<String, Object> syncUserWithExternal(String inum, Map<String, String> conf) {
        Map<String, Object> result = new HashMap<>();
        try {
            // Load config using CdiUtil or static ConfigService
            Map<String, String> config = new HashMap<>();
            if (conf == null) {
            result.put("status", "error");
            result.put("message", "Configuration is null");
            return result;
        }

            String publicKey = conf.get("PUBLIC_KEY");
            String privateKey = conf.get("PRIVATE_KEY");

            if (publicKey == null || privateKey == null) {
                result.put("status", "error");
                result.put("message", "PUBLIC_KEY or PRIVATE_KEY missing in config");
                return result;
            }

            // Generate HMAC-SHA256 signature (hex lowercase)
            String signature;
            try {
                javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
                javax.crypto.spec.SecretKeySpec secretKey = new javax.crypto.spec.SecretKeySpec(
                        privateKey.getBytes(java.nio.charset.StandardCharsets.UTF_8),
                        "HmacSHA256");
                mac.init(secretKey);
                byte[] hashBytes = mac.doFinal(inum.getBytes(java.nio.charset.StandardCharsets.UTF_8));
                StringBuilder hex = new StringBuilder();
                for (byte b : hashBytes) {
                    String h = Integer.toHexString(0xff & b);
                    if (h.length() == 1)
                        hex.append('0');
                    hex.append(h);
                }
                signature = hex.toString().toLowerCase();
            } catch (Exception ex) {
                result.put("status", "error");
                result.put("message", "Failed to generate signature: " + ex.getMessage());
                return result;
            }

            // Build webhook URL
            String url = String.format("https://api.phiwallet.com/v1/webhooks/users/%s/sync", inum);

            // HTTP request
            HttpClient client = HttpClient.newHttpClient();
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .header("X-AUTH-CLIENT", publicKey)
                    .header("X-HMAC-SIGNATURE", signature)
                    .POST(HttpRequest.BodyPublishers.noBody())
                    .build();

            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            System.out.println(String.format("Webhook sync response status: %d, body: %s",
                    response.statusCode(), response.body()));

            if (response.statusCode() == 200) {
                result.put("status", "success");
            } else {
                result.put("status", "error");
                result.put("message", response.body());
            }

            return result;

        } catch (Exception e) {
            e.printStackTrace();
            result.put("status", "error");
            result.put("message", e.getMessage());
            return result;
        }
    }

    @Override
    public boolean sendAccountCreationNotificationEmail(String to, String username, String lang) {
        try {
            ConfigurationService configService = CdiUtil.bean(ConfigurationService.class);
            SmtpConfiguration smtpConfig = configService.getConfiguration().getSmtpConfiguration();

            if (smtpConfig == null) {
                logger.error("SMTP configuration missing.");
                return false;
            }

            String preferredLang = (lang != null && !lang.isEmpty()) ? lang.toLowerCase() : "en";
            Map<String, String> templateData = null;

            switch (preferredLang) {
                case "ar":
                    templateData = AccountCreationTemplateAr.get(username);
                    break;
                case "es":
                    templateData = AccountCreationTemplateEs.get(username);
                    break;
                case "fr":
                    templateData = AccountCreationTemplateFr.get(username);
                    break;
                case "id":
                    templateData = AccountCreationTemplateId.get(username);
                    break;
                case "pt":
                    templateData = AccountCreationTemplatePt.get(username);
                    break;
                default:
                    templateData = AccountCreationTemplateEn.get(username);
                    break;
            }

            if (templateData == null || !templateData.containsKey("body")) {
                logger.error("No email template found for language: {}", preferredLang);
                return false;
            }

            String subject = templateData.getOrDefault("subject", "Your Username Information");
            String htmlBody = templateData.get("body");

            if (htmlBody == null || htmlBody.isEmpty()) {
                logger.error("Email HTML body is empty for language: {}", preferredLang);
                return false;
            }

            // Plain text version
            String textBody = htmlBody.replaceAll("\\<.*?\\>", "");

            MailService mailService = CdiUtil.bean(MailService.class);

            boolean sent = mailService.sendMailSigned(
                    smtpConfig.getFromEmailAddress(),
                    smtpConfig.getFromName(),
                    to,
                    null,
                    subject,
                    textBody,
                    htmlBody);

            if (sent) {
                LogUtils.log("Localized username update email sent successfully to %", to);
            } else {
                LogUtils.log("Failed to send localized username update email to %", to);
            }

            return sent;

        } catch (Exception e) {
            LogUtils.log("Failed to send username update email: %", e.getMessage());
            return false;
        }
    }

}

