import { buildQuoteEmail } from "./services-inquiry.js";

const quoteForm = document.querySelector("#quote-form");
const packageField = document.querySelector("#quote-package");
const formStatus = document.querySelector("#quote-status");

document.querySelectorAll("[data-package]").forEach((link) => {
  link.addEventListener("click", () => {
    packageField.value = link.dataset.package;
  });
});

quoteForm.addEventListener("submit", (event) => {
  event.preventDefault();
  if (!quoteForm.reportValidity()) return;

  const values = Object.fromEntries(new FormData(quoteForm).entries());
  const { subject, body } = buildQuoteEmail(values);
  formStatus.textContent = "Opening your email app with the request details…";
  window.location.href = `mailto:josh.delacruz19@gmail.com?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`;
});
