export function getAdminEmails() {
  const rawEmails = [process.env.ADMIN_EMAILS, process.env.ADMIN_EMAIL]
    .filter(Boolean)
    .join(',');

  return rawEmails
    .split(',')
    .map((email) => email.trim().toLowerCase())
    .filter(Boolean);
}