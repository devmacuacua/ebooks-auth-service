package mz.ebooks.auth.entity;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Table(name = "users")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(columnDefinition = "uuid", updatable = false, nullable = false)
    private UUID id;

    @Column(nullable = false, unique = true, length = 255)
    private String email;

    @Column(name = "email_verified")
    private LocalDateTime emailVerified;

    @Column(name = "password_hash", length = 255)
    private String passwordHash;

    @Column(nullable = false, length = 255)
    private String name;

    @Column(length = 512)
    private String avatar;

    @Column(length = 50)
    private String phone;

    @Column(nullable = false, length = 20)
    @Builder.Default
    private String role = "CUSTOMER";

    @Column(name = "is_active", nullable = false)
    @Builder.Default
    private boolean isActive = true;

    @Column(name = "notif_order_updates", nullable = false)
    @Builder.Default
    private boolean notifOrderUpdates = true;

    @Column(name = "notif_new_books", nullable = false)
    @Builder.Default
    private boolean notifNewBooks = true;

    @Column(name = "notif_subscription_alerts", nullable = false)
    @Builder.Default
    private boolean notifSubscriptionAlerts = true;

    @Column(name = "notif_promotions", nullable = false)
    @Builder.Default
    private boolean notifPromotions = false;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;

    public boolean hasRole(String roleName) {
        return this.role != null && this.role.equalsIgnoreCase(roleName);
    }

    public boolean isEmailVerified() {
        return this.emailVerified != null;
    }
}
