document.addEventListener('DOMContentLoaded', function () {
    // Hamburger menu toggle
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
    const signUpButton = document.querySelector(".sign-up");
    const signInButton = document.querySelector(".sign-in");
    const container = document.getElementById("container");

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




// Handle the sign-up form submission
const signUpForm = document.querySelector(".sign-up-container form");
signUpForm.addEventListener("submit", function (event) {
    event.preventDefault(); // Prevent the default form submission

    const name = signUpForm.querySelector("input[type='text']").value;
    const email = signUpForm.querySelector("input[type='email']").value;
    const password = signUpForm.querySelector("input[type='password']").value;

    // Send the sign-up data to the server using fetch
    fetch("index.php", {
        method: "POST",
        headers: {
            "Content-Type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
            action: "signup",
            name: name,
            email: email,
            password: password,
        }),
    })
    .then(response => response.json())
    .then(data => {
        if (data.error) {
            alert(data.error); // Display error message
        } else {
            // Redirect based on role - default to About page for new users
            window.location.href = "About.html"; // New users go to About page
        }
    })
    .catch(error => {
        console.error("Error during sign-up:", error);
    });
});

// Handle the sign-in form submission
const signInForm = document.querySelector(".sign-in-container form");
signInForm.addEventListener("submit", function (event) {
    event.preventDefault(); // Prevent the default form submission

    const email = signInForm.querySelector("input[type='email']").value;
    const password = signInForm.querySelector("input[type='password']").value;

    // Send the sign-in data to the server using fetch
    fetch("index.php", {
        method: "POST",
        headers: {
            "Content-Type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
            action: "login",
            email: email,
            password: password,
        }),
    })
    .then(response => response.json())
    .then(data => {
        if (data.error) {
            alert(data.error); // Display error message
        } else if (data.success) {
            // Redirect based on the role
            window.location.href = data.redirect; // Redirect according to role from PHP
        }
    })
    .catch(error => {
        console.error("Error during sign-in:", error);
    });
});




// search.js

document.addEventListener("DOMContentLoaded", function() {
    const searchInput = document.querySelector('.search__input');
    const items = document.querySelectorAll('.searchable'); // Class for elements to search

    searchInput.addEventListener('input', function() {
        const query = searchInput.value.toLowerCase();

        items.forEach(item => {
            const title = item.querySelector('h3').textContent.toLowerCase();
            const summary = item.querySelector('p').textContent.toLowerCase();
            
            // Check if the query matches the title or summary
            if (title.includes(query) || summary.includes(query)) {
                item.style.display = ''; // Show the item
            } else {
                item.style.display = 'none'; // Hide the item
            }
        });
    });
});


});
