document.addEventListener("DOMContentLoaded", () => {
    const loginForm = document.querySelector(".login-form");
    const registerForm = document.querySelector(".register-form");
    const showLogin = document.getElementById("showLogin");
    const showRegister = document.getElementById("showRegister");

    // Show login by default
    loginForm.style.display = "block";

    showRegister.addEventListener("click", () => {
        loginForm.classList.add("hidden");
        registerForm.classList.remove("hidden");
        registerForm.style.display = "block";
    });

    showLogin.addEventListener("click", () => {
        registerForm.classList.add("hidden");
        loginForm.classList.remove("hidden");
        loginForm.style.display = "block";
    });
});

function togglePassword(id) {
    const input = document.getElementById(id);
    input.type = input.type === "password" ? "text" : "password";
}
