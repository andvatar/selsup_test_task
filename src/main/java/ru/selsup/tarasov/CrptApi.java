package ru.selsup.tarasov;

import com.google.gson.*;
import com.google.gson.annotations.JsonAdapter;
import com.google.gson.annotations.SerializedName;
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.core5.http.*;
import org.apache.hc.core5.http.io.entity.StringEntity;

import java.io.*;
import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;


public class CrptApi {

    private final TimeUnit timeUnit;
    private final int requestLimit;

    private static final String REQUEST_URL = "https://ismp.crpt.ru/api/v3/lk/documents/create";

    private final AtomicInteger requestNumber = new AtomicInteger(0);
    private LocalDateTime startTime;

    private final ReentrantLock lock = new ReentrantLock(true);
    private final Condition tooManyRequests = lock.newCondition();

    public CrptApi(TimeUnit timeUnit, int requestLimit) {
        this.timeUnit = timeUnit;
        this.requestLimit = requestLimit;
        this.startTime = LocalDateTime.now();
    }

    public void AddProducts(Document document, String signature) throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException, IOException, InvalidKeySpecException, SignatureException, InvalidKeyException {
        CheckTime();

        if(requestNumber.getAndIncrement() < requestLimit) {
            SendProducts(document, signature);
        }
        else
        {
            long waitTime = ChronoUnit.MILLIS.between(LocalDateTime.now(), getStartDate().plus(1,timeUnit.toChronoUnit()));
            if(waitTime > 0) {
                lock.lock();
                try {
                    tooManyRequests.await(waitTime, TimeUnit.MILLISECONDS);
                } catch (InterruptedException e) {
                    throw new RuntimeException("The process was interrupted while waiting for the next time period", e);
                }
                finally {
                    lock.unlock();
                }
            }
            AddProducts(document, signature);
        }
    }

    private void SendProducts(Document document, String signature) throws NoSuchAlgorithmException, InvalidKeySpecException, SignatureException, InvalidKeyException {
        Gson gson = new GsonBuilder()
                    .registerTypeAdapter(LocalDate.class, new LocalDateAdapter())
                    .create();
        String json = gson.toJson(document);

        HttpPost httpPost = getHttpPost(json, signature);

        try (
                    CloseableHttpClient client = HttpClients.createDefault();
                    ClassicHttpResponse response = client
                            .execute(httpPost, classicHttpResponse -> classicHttpResponse)
            ) {
                if(response.getCode() != 200) {
                    throw new RuntimeException("The request was not successful: " + response.getReasonPhrase());
                }
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
    }

    private String getEncodedSignature(String signature, String json) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException {
        KeyFactory kf = KeyFactory.getInstance("RSA");

        PKCS8EncodedKeySpec keySpecPKCS8 = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(signature));
        PrivateKey privateKey = kf.generatePrivate(keySpecPKCS8);

        Signature sig = Signature.getInstance("SHA1withRSA");
        sig.initSign(privateKey);
        sig.update(json.getBytes(StandardCharsets.UTF_8));
        byte[] signatureBytes = sig.sign();

        return Base64.getEncoder().encodeToString(signatureBytes);
    }

    private HttpPost getHttpPost(String json, String signature) throws NoSuchAlgorithmException, InvalidKeySpecException, SignatureException, InvalidKeyException {
        String EncodedJson = getEncodedSignature(signature, json);
        HttpPost httpPost = new HttpPost(REQUEST_URL + "?signature=" + EncodedJson);
        httpPost.setHeader("content-type", "application/json;charset=UTF-8");
        httpPost.setEntity(new StringEntity(json, ContentType.APPLICATION_JSON));

        return httpPost;
    }



    private void CheckTime() {
        lock.lock();
        try{
            if(startTime.plus(1, timeUnit.toChronoUnit()).isBefore(LocalDateTime.now())) {
                requestNumber.set(0);
                startTime = LocalDateTime.now();
            }
        }
        finally {
            lock.unlock();
        }
    }

    private LocalDateTime getStartDate() {
        lock.lock();
        try{
            return startTime;
        }
        finally {
            lock.unlock();
        }
    }

    private static class LocalDateAdapter implements JsonSerializer<LocalDate> {
        @Override
        public JsonElement serialize(LocalDate date, java.lang.reflect.Type typeOfSrc, JsonSerializationContext context) {
            return new JsonPrimitive(date.format(DateTimeFormatter.ISO_LOCAL_DATE));
        }
    }

    private static class InnDescGsonAdapter  implements JsonSerializer<String> {
        @Override
        public JsonElement serialize(String s, Type type, JsonSerializationContext jsonSerializationContext) {
            JsonObject result = new JsonObject();
            result.add("participantInn", new JsonPrimitive(s));
            return result;
        }
    }

    public record Product(String certificateDocument,
                          LocalDate certificateDocumentDate,
                          String certificateDocumentNumber,
                          String ownerInn,
                          String producerInn,
                          LocalDate productionDate,
                          String tnvedCode,
                          String uitCode,
                          String uituCode) {
    }

    public record Document(
                           @SerializedName("description")
                           @JsonAdapter(InnDescGsonAdapter.class)
                           String participantInnDesc,
                           String docId,
                           String docType,
                           boolean importRequest,
                           String ownerInn,
                           String participantInn,
                           String producerInn,
                           LocalDate productionDate,
                           String productionType,
                           List<Product> products,
                           LocalDate regDate,
                           String regNumber) {
    }
}
