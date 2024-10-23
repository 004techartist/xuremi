document.addEventListener('DOMContentLoaded', function () {

    const hamburger = document.getElementById('hamburger');
    if (hamburger) {
        hamburger.addEventListener('click', function () {
            const menu = document.querySelector('.menu ul');
            if (menu) {
                menu.classList.toggle('expanded');
            }
        });
    }
    // Card carousel functionality
    const cards = document.querySelectorAll('.card');
    let currentIndex = 0;
    cards[currentIndex].classList.add('active');

    setInterval(() => {
        const currentCard = cards[currentIndex];
        const nextIndex = (currentIndex + 1) % cards.length;
        const nextCard = cards[nextIndex];

        currentCard.classList.remove('active');
        nextCard.classList.add('active');
        currentIndex = nextIndex;
    }, 3000);

    // Event listeners for sign-up and sign-in forms
    const signUpButton = document.getElementById('signUp');
    const signInButton = document.getElementById('signIn');
    const container = document.querySelector('.container');
    const authButtons = document.querySelectorAll('.auth-buttons .btn');

    container.style.display = 'none';

    signUpButton.addEventListener('click', () => {
        container.classList.add('right-panel-active');
        container.style.display = 'flex';
    });

    signInButton.addEventListener('click', () => {
        container.classList.remove('right-panel-active');
        container.style.display = 'flex';
    });

    window.addEventListener('click', (e) => {
        if (!container.contains(e.target) && !e.target.classList.contains('btn')) {
            container.style.display = 'none';
        }
    });

    const signUpForm = document.querySelector('.sign-up-container form');
    signUpForm.addEventListener('submit', (e) => {
        e.preventDefault();
    
        const name = signUpForm.querySelector('input[placeholder="Name"]').value;
        const email = signUpForm.querySelector('input[placeholder="Email"]').value;
        const password = signUpForm.querySelector('input[placeholder="Password"]').value;
    
        console.log("Form data before submission:", { name, email, password });
    
        fetch('http://localhost:5000/signup', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ name, email, password })
        })
        .then(response => {
            console.log("Response status:", response.status); // Log response status
            if (!response.ok) {
                return response.text().then(text => { throw new Error(text); });
            }
            return response.json();
        })
        .then(data => {
            console.log("Server response:", data);
            alert(data.message);
        })
        .catch(error => {
            console.error('Error during sign-up:', error);
            alert("An error occurred during sign-up: " + error.message);
        });
    });
    
    const signInForm = document.querySelector('.sign-in-container form');
    signInForm.addEventListener('submit', (e) => {
        e.preventDefault();
        console.log("Sign-in form submitted"); // Add this line
        const email = signInForm.querySelector('input[placeholder="Email"]').value;
        const password = signInForm.querySelector('input[placeholder="Password"]').value;
    
        fetch('http://localhost:5000/signin', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ email, password })
        })
        .then(response => response.json())
        .then(data => {
            console.log("Server response:", data); // Log the server response
            alert(data.message);

            // Redirect based on role
            if (data.message === "Login successful") {
                window.location.href = data.redirect;  // Redirect based on the role
            }
        })
        .catch(error => {
            console.error('Error:', error);
            alert("Error during sign-in. Please check your credentials.");
        });
    });

    authButtons.forEach(button => {
        button.addEventListener('click', () => {
            container.style.display = 'flex';
        });
    });






    






}); 

