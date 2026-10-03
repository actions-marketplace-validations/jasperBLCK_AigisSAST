const comments = document.querySelector("#comments");
const stripeSecret = import.meta.env.VITE_STRIPE_SECRET_KEY;

export function render(comment) {
  comments.innerHTML += `<p>${comment.text}</p>`;
}

export function runFormula(formula) {
  return eval(formula);
}
