package mz.ebooks.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class NotificationPrefsDto {
    private boolean orderUpdates;
    private boolean newBooks;
    private boolean subscriptionAlerts;
    private boolean promotions;
}
