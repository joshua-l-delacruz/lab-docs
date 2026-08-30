export function buildQuoteEmail(values) {
  const value = (key, fallback = "Not provided") => String(values[key] || fallback).trim();
  const projectPackage = value("package", "Project inquiry");
  const subject = `Project fit request — ${projectPackage}`;
  const body = [
    "Hello Joshua,", "", "I would like to request a project fit review and written quote.", "",
    `Name: ${value("name")}`,
    `Email: ${value("email")}`,
    `Business or organization: ${value("organization")}`,
    `Service: ${projectPackage}`,
    `Available budget: ${value("budget")}`,
    `Project stage: ${value("stage")}`,
    `Target launch: ${value("launch-date", "Flexible")}`, "",
    "Users and problem to solve:", value("audience"), "",
    "Must-have features and successful outcome:", value("success-criteria"), "",
    "Existing site, repository, or references:", value("reference-links"), "",
    "I understand that the written scope will confirm deliverables, exclusions, timeline, price, and the deposit required to reserve the schedule."
  ].join("\n");
  return { subject, body };
}
