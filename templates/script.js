function showLogin() {
    document.getElementById('loginForm').classList.remove('hidden');
    document.getElementById('registerForm').classList.add('hidden');
    document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
    event.target.classList.add('active');
}

function showRegister() {
    document.getElementById('registerForm').classList.remove('hidden');
    document.getElementById('loginForm').classList.add('hidden');
    document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
    event.target.classList.add('active');
}

// Database simulation (replace with actual database implementation)
const db = {
    users: [],
    events: [],
    clubs: [],
    departments: [],
    fests: []
};

// User Authentication
document.getElementById('loginForm')?.addEventListener('submit', function(e) {
    e.preventDefault();
    const email = this.querySelector('input[type="email"]').value;
    const password = this.querySelector('input[type="password"]').value;
    const role = this.querySelector('select[name="role"]').value;
    
    // Simulate authentication
    login(email, password, role);
});

// document.getElementById('registerForm')?.addEventListener('submit', function(e) {
//     e.preventDefault();
//     const name = this.querySelector('input[type="text"]').value;
//     const email = this.querySelector('input[type="email"]').value;
//     const password = this.querySelector('input[type="password"]').value;
//     const role = this.querySelector('select[name="role"]').value;
    
//     // Simulate registration
//     register(name, email, password, role);
// });


function login(email, password, role) {
    // Simulate login logic
    const user = db.users.find(u => u.email === email && u.password === password);
    if (user) {
        localStorage.setItem('currentUser', JSON.stringify(user));
        window.location.href = `${role}.html`;
    } else {
        alert('Invalid credentials');
    }
}

// function register(name, email, password, role) {
//     // Simulate registration logic
//     const newUser = { id: Date.now(), name, email, password, role };
//     db.users.push(newUser);
//     localStorage.setItem('currentUser', JSON.stringify(newUser));
//     window.location.href = `${role}.html`;
// }

function logout() {
    localStorage.removeItem('currentUser');
    window.location.href = 'index.html';
}

// Profile Management
function showEditProfile() {
    document.getElementById('editProfile').classList.remove('hidden');
}

function closeEditProfile() {
    document.getElementById('editProfile').classList.add('hidden');
}

function addPosition() {
    const positionsList = document.getElementById('positionsList');
    const newPosition = document.createElement('div');
    newPosition.innerHTML = `
        <select required>
            <option value="">Select Club/Fest</option>
            <option value="tech">Tech Club</option>
            <option value="cultural">Cultural Club</option>
            <!-- Add more options -->
        </select>
        <input type="text" placeholder="Position" required>
        <button type="button" onclick="this.parentElement.remove()">Remove</button>
    `;
    positionsList.appendChild(newPosition);
}

// Event Management Functions
function addEvent(type, details) {
    const event = {
        id: Date.now(),
        type,
        ...details,
        createdAt: new Date()
    };
    db.events.push(event);
    return event;
}

function getEvents(filters = {}) {
    return db.events.filter(event => {
        if (filters.type && event.type !== filters.type) return false;
        if (filters.department && event.department !== filters.department) return false;
        return true;
    });
}

// Calendar Implementation
function initializeCalendar() {
    const calendar = document.getElementById('calendar');
    if (!calendar) return;

    // Implement calendar visualization
    // This is a placeholder - you might want to use a library like FullCalendar
    const events = getEvents();
    calendar.innerHTML = `
        <h2>Events Calendar</h2>
        <div class="events-list">
            ${events.map(event => `
                <div class="event-card">
                    <h3>${event.title}</h3>
                    <p>Date: ${event.date}</p>
                    <p>Venue: ${event.venue}</p>
                    <p>Type: ${event.type}</p>
                </div>
            `).join('')}
        </div>
    `;
}

// Initialize components
document.addEventListener('DOMContentLoaded', function() {
    initializeCalendar();
});