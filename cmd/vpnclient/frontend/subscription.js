export function subscriptionExpiry(value, now = new Date()) {
  const date = new Date(value || "");
  if (!Number.isFinite(date.getTime()) || date.getFullYear() <= 2000) {
    return { text: "Провайдер не указал срок подписки", expired: false, soon: false };
  }
  const expired = date.getTime() <= now.getTime();
  return {
    text: (expired ? "Подписка истекла " : "Подписка действует до ") + date.toLocaleDateString("ru-RU"),
    expired,
    soon: !expired && date.getTime() - now.getTime() <= 3 * 86400000,
    detail: date.toLocaleString("ru-RU") + " (местное время)",
  };
}
