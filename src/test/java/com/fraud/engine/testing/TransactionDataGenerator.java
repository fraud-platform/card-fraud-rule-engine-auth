package com.fraud.engine.testing;

import com.github.javafaker.Faker;
import com.fraud.engine.domain.TransactionContext;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

public class TransactionDataGenerator {

    private static final Faker faker = new Faker();

    public enum CardNetwork {
        VISA, MASTERCARD, AMEX, DISCOVER, DINERS, JCB, UNIONPAY
    }

    public enum TransactionType {
        PURCHASE, AUTHORIZATION, REFUND, REVERSAL, TRANSFER, CASH_ADVANCE, QUASI_CASH
    }

    public enum EntryMode {
        CHIP, SWIPE, ECOM, CONTACTLESS, MAGSTRIPE, FALLBACK
    }

    public enum Country {
        US, GB, CA, AU, DE, FR, IT, ES, NL, BR, IN, JP, CN, MX, RU, ZA, SG, HK
    }

    public enum HighRiskCountry {
        RU, CN, NG, PK, BD, UA, KP
    }

    private static final String[] HIGH_RISK_MCCS = {
        "5967", "7995", "7801", "7994", "5122", "5912", "5962", "4829", "6051", "6012"
    };

    private static final String[] LOW_RISK_MCCS = {
        "5411", "5541", "5812", "5814", "5732", "5311", "5651", "5691", "7230", "5999"
    };

    private static String randomRealisticMcc() {
        return faker.random().nextDouble() < 0.70
            ? faker.options().option(LOW_RISK_MCCS)
            : faker.options().option(HIGH_RISK_MCCS);
    }

    public static TransactionContext randomTransaction() {
        return randomTransaction(null);
    }

    public static TransactionContext randomTransaction(String cardHash) {
        TransactionContext txn = new TransactionContext();

        txn.setTransactionId(faker.finance().iban());
        txn.setCardHash(cardHash != null ? cardHash : hashCard(faker.finance().creditCard()));
        txn.setAmount(BigDecimal.valueOf(faker.number().numberBetween(1, 10000)));
        txn.setCurrency(faker.options().option("USD", "EUR", "GBP", "CAD", "AUD", "JPY", "INR"));
        txn.setMerchantId("merch_" + faker.number().digits(8));
        txn.setMerchantName(faker.company().name());
        txn.setMerchantCategory(faker.commerce().department());
        txn.setMerchantCategoryCode(randomRealisticMcc());
        txn.setCardPresent(faker.random().nextBoolean());
        txn.setTransactionType(faker.options().option(TransactionType.values()).toString());
        txn.setEntryMode(faker.options().option(EntryMode.values()).toString());

        String country = (faker.random().nextBoolean() && faker.random().nextBoolean())
            ? faker.options().option(HighRiskCountry.values()).toString()
            : faker.options().option(Country.values()).toString();
        txn.setCountryCode(country);

        txn.setIpAddress(faker.internet().ipV4Address());
        txn.setDeviceId("device_" + faker.internet().uuid());
        txn.setEmail(faker.internet().emailAddress());
        txn.setPhone(faker.phoneNumber().cellPhone());
        txn.setTimestamp(Instant.now());

        txn.setCardNetwork(faker.options().option(CardNetwork.values()).toString());
        txn.setCardBin(faker.finance().creditCard().substring(0, 6));
        txn.setCardLogo(faker.options().option("VISA", "MC", "AMEX", "DISCOVER"));

        Map<String, Object> customFields = new HashMap<>();
        customFields.put("loyalty_tier", faker.options().option("BRONZE", "SILVER", "GOLD", "PLATINUM"));
        customFields.put("ip_risk_score", faker.number().numberBetween(0, 100));
        customFields.put("device_trusted", faker.random().nextBoolean());
        txn.setCustomFields(customFields);

        return txn;
    }

    public static TransactionContext highRiskTransaction() {
        TransactionContext txn = randomTransaction();

        txn.setAmount(BigDecimal.valueOf(faker.number().numberBetween(5000, 15000)));
        txn.setCountryCode(faker.options().option(HighRiskCountry.values()).toString());
        txn.setIpAddress(faker.internet().ipV4Address());
        txn.setMerchantId(faker.commerce().productName() + "_HIGH_RISK");
        txn.setTransactionType(TransactionType.PURCHASE.toString());

        Map<String, Object> customFields = txn.getCustomFields();
        customFields.put("ip_risk_score", 90);
        customFields.put("device_trusted", false);
        customFields.put("transaction_velocity_24h", faker.number().numberBetween(50, 200));

        return txn;
    }

    public static TransactionContext lowRiskTransaction() {
        TransactionContext txn = randomTransaction();

        txn.setAmount(BigDecimal.valueOf(faker.number().numberBetween(1, 100)));
        txn.setCountryCode(faker.options().option("US", "GB", "CA", "AU").toString());
        txn.setIpAddress("192.168." + faker.number().numberBetween(1, 255) + "." + faker.number().numberBetween(1, 255));
        txn.setCardPresent(true);

        Map<String, Object> customFields = txn.getCustomFields();
        customFields.put("ip_risk_score", 5);
        customFields.put("device_trusted", true);
        customFields.put("user_account_age_days", faker.number().numberBetween(100, 3650));

        return txn;
    }

    public static TransactionContext[] generateBatch(int count) {
        TransactionContext[] batch = new TransactionContext[count];
        for (int i = 0; i < count; i++) {
            double risk = faker.random().nextDouble();
            if (risk < 0.10) {
                batch[i] = highRiskTransaction();
            } else if (risk < 0.30) {
                batch[i] = randomTransaction();
            } else {
                batch[i] = lowRiskTransaction();
            }
        }
        return batch;
    }

    public static TransactionContext[] generateBatchForCard(int count, String cardHash) {
        TransactionContext[] batch = new TransactionContext[count];
        for (int i = 0; i < count; i++) {
            batch[i] = randomTransaction(cardHash);
        }
        return batch;
    }

    public static TransactionContext customTransaction(
            BigDecimal amount,
            String currency,
            String countryCode,
            String merchantId) {
        TransactionContext txn = new TransactionContext();

        txn.setTransactionId("txn_" + UUID.randomUUID().toString().substring(0, 8));
        txn.setCardHash(hashCard("4111111111111111"));
        txn.setAmount(amount);
        txn.setCurrency(currency != null ? currency : "USD");
        txn.setMerchantId(merchantId != null ? merchantId : "merch_default");
        txn.setMerchantName("Default Merchant");
        txn.setMerchantCategory("default");
        txn.setMerchantCategoryCode("5411");
        txn.setCountryCode(countryCode != null ? countryCode : "US");
        txn.setIpAddress("192.168.1.1");
        txn.setDeviceId("device_default");
        txn.setEmail("test@example.com");
        txn.setPhone("+1234567890");
        txn.setTimestamp(Instant.now());
        txn.setTransactionType("PURCHASE");
        txn.setEntryMode("ECOM");
        txn.setCardNetwork("VISA");
        txn.setCardBin("411111");

        return txn;
    }

    public static String hashCard(String cardNumber) {
        return "hash_" + Integer.toHexString(cardNumber.hashCode());
    }

    public static String randomCardHash() {
        return "hash_" + faker.crypto().toString();
    }
}
