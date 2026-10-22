package com.workstream.ats;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;

// POST /webhooks/applications
// Receives application events from the job-board and text-to-apply providers.
//
// The provider signs each request: X-Provider-Signature is a hex HMAC-SHA256
// of the raw request body. Deliveries are retried up to 5 times if we do not
// return a 2xx within 5 seconds, and they can arrive out of order.
//
// Example event:
//   {
//     "event_id": "evt_81fa30",          // unique per event
//     "type": "application.created",      // or "application.updated"
//     "position_id": 4412,
//     "status": "applied",                // pipeline stage, on updates
//     "applicant": { "name": "...", "phone": "...", "email": "..." },
//     "answers": [ { "question_id": 9, "value": "..." } ],
//     "occurred_at": "2026-08-28T09:14:03Z"
//   }
@RestController
public class ApplicationWebhookController {

    private static final Logger log = LoggerFactory.getLogger(ApplicationWebhookController.class);

    private final JdbcTemplate jdbc;
    private final SmsClient sms;
    private final ExecutorService answerWriters;
    private final ObjectMapper mapper;

    public ApplicationWebhookController(JdbcTemplate jdbc, SmsClient sms, ExecutorService answerWriters, ObjectMapper mapper) {
        this.jdbc = jdbc;
        this.sms = sms;
        this.answerWriters = answerWriters;
        this.mapper = mapper;
    }

    @PostMapping("/webhooks/applications")
    public ResponseEntity<String> handle(
            @RequestHeader(value = "X-Provider-Signature", required = false) String signature,
            @RequestBody JsonNode event) throws Exception {

        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(System.getenv("PROVIDER_SECRET").getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        String expected = HexFormat.of().formatHex(mac.doFinal(mapper.writeValueAsBytes(event)));
        if (signature != null && !signature.equals(expected)) {
            return ResponseEntity.status(401).body("bad signature");
        }

        try {
            List<Map<String, Object>> found = jdbc.queryForList(
                "SELECT id, company_id, title, hiring_manager_id FROM positions WHERE id = ?",
                event.get("position_id").asInt());
            if (found.isEmpty()) {
                return ResponseEntity.status(400).body("unknown position");
            }
            Map<String, Object> position = found.get(0);

            jdbc.execute("BEGIN");

            String phone = event.get("applicant").get("phone").asText().replaceAll("\\D", "");
            List<Map<String, Object>> existing = jdbc.queryForList(
                "SELECT id, name FROM applicants WHERE phone = ?", phone);
            Map<String, Object> applicant;
            if (existing.isEmpty()) {
                applicant = jdbc.queryForMap(
                    "INSERT INTO applicants (name, phone, email) VALUES (?, ?, ?) RETURNING id, name",
                    event.get("applicant").get("name").asText(), phone, event.get("applicant").get("email").asText());
            } else {
                applicant = existing.get(0);
            }

            if ("application.created".equals(event.get("type").asText())) {
                Integer applicationId = jdbc.queryForObject(
                    "INSERT INTO applications (applicant_id, position_id, status, applied_at) " +
                    "VALUES (?, ?, 'applied', ?) RETURNING id",
                    Integer.class,
                    applicant.get("id"), event.get("position_id").asInt(), event.get("occurred_at").asText());

                for (JsonNode a : event.get("answers")) {
                    answerWriters.submit(() -> jdbc.update(
                        "INSERT INTO application_answers (application_id, question_id, value) " +
                        "VALUES (" + applicationId + ", " + a.get("question_id").asInt() + ", '" + a.get("value").asText() + "')"));
                }
            } else {
                jdbc.update(
                    "UPDATE applications SET status = ? WHERE applicant_id = ? AND position_id = ?",
                    event.get("status").asText(), applicant.get("id"), event.get("position_id").asInt());
            }

            jdbc.execute("COMMIT");

            sms.send(phone, "Hi " + event.get("applicant").get("name").asText()
                + ", thanks for applying to " + position.get("title") + "! We'll text you here about next steps.");

            Map<String, Object> manager = jdbc.queryForMap(
                "SELECT phone FROM users WHERE id = ?", position.get("hiring_manager_id"));
            sms.send((String) manager.get("phone"),
                "New applicant for " + position.get("title") + ": " + event.get("applicant").get("name").asText());

            log.info("application processed type={} applicant={} answers={} position={}",
                event.get("type").asText(), event.get("applicant"), event.get("answers"), position.get("title"));

            return ResponseEntity.status(200).body("ok");
        } catch (Exception err) {
            log.error("webhook failed");
            return ResponseEntity.status(500).body("error");
        }
    }
}
