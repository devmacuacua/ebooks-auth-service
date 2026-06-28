package mz.ebooks.auth.messaging;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthEventPublisher {

    private static final String EXCHANGE = "ebooks.events";

    private final RabbitTemplate rabbitTemplate;

    /**
     * Publish any event payload to the shared topic exchange.
     *
     * @param routingKey RabbitMQ routing key, e.g. "user.registered"
     * @param payload    Arbitrary object that will be serialised to JSON
     */
    public void publishEvent(String routingKey, Object payload) {
        try {
            rabbitTemplate.convertAndSend(EXCHANGE, routingKey, payload);
            log.debug("Published event [{}] to exchange [{}]", routingKey, EXCHANGE);
        } catch (Exception e) {
            log.error("Failed to publish event [{}]: {}", routingKey, e.getMessage(), e);
        }
    }

    /**
     * Convenience method for publishing a user.registered event.
     */
    public void publishUserRegistered(String userId, String name, String email, String verificationUrl) {
        publishEvent("user.registered", Map.of(
                "userId", userId,
                "name", name,
                "email", email,
                "verificationUrl", verificationUrl
        ));
    }

    /**
     * Convenience method for publishing a user.password-reset-requested event.
     */
    public void publishPasswordResetRequested(String email, String name, String resetUrl) {
        publishEvent("user.password-reset-requested", Map.of(
                "email", email,
                "name", name,
                "resetUrl", resetUrl
        ));
    }

    /**
     * Convenience method for publishing a user.email-verified event.
     */
    public void publishEmailVerified(String userId, String email) {
        publishEvent("user.email-verified", Map.of(
                "userId", userId,
                "email", email
        ));
    }
}
