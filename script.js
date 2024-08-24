/*
  This is your site JavaScript code - you can add interactivity!
*/

// Print a message in the browser's dev tools console each time the page loads
// Use your menus or right-click / control-click and choose "Inspect" > "Console"
console.log("Hello 🌎");

/* 
Make the "Click me!" button move when the visitor clicks it:
- First add the button to the page by following the steps in the TODO 🚧
*/
const btn = document.querySelector("button"); // Get the button from the page
if (btn) { // Detect clicks on the button
  btn.onclick = function () {
    // The 'dipped' class in style.css changes the appearance on click
    btn.classList.toggle("dipped");
  };
}


// ----- GLITCH STARTER PROJECT HELPER CODE -----

// Open file when the link in the preview is clicked
let goto = (file, line) => {
  window.parent.postMessage(
    { type: "glitch/go-to-line", payload: { filePath: file, line: line } }, "*"
  );
};
// Get the file opening button from its class name
const filer = document.querySelectorAll(".fileopener");
filer.forEach((f) => {
  f.onclick = () => { goto(f.dataset.file, f.dataset.line); };
});

document.addEventListener('DOMContentLoaded', () => {
    // Interactive bubble
    const interBubble = document.querySelector('.interactive');
    let curX = 0;
    let curY = 0;
    let tgX = 0;
    let tgY = 0;

    const move = () => {
        curX += (tgX - curX) / 20;
        curY += (tgY - curY) / 20;
        interBubble.style.transform = `translate(${Math.round(curX)}px, ${Math.round(curY)}px)`;
        requestAnimationFrame(move);
    };

    window.addEventListener('mousemove', (event) => {
        tgX = event.clientX;
        tgY = event.clientY;
    });

    move();

    // Resume data loading
    const loadResumeData = async () => {
        try {
            const response = await fetch('fowler_resume222.json');
            const data = await response.json();

            document.getElementById('name').textContent = data.name;
            document.getElementById('contact-info').innerHTML = `
                ${data.contact.address}<br>
                ${data.contact.phone}<br>
                <a href="mailto:${data.contact.email}">${data.contact.email}</a>
            `;
            document.getElementById('professional-summary').textContent = data.professionalSummary;

            const renderList = (elementId, items, itemRenderer) => {
                const list = document.getElementById(elementId);
                items.forEach(item => {
                    const li = document.createElement('li');
                    li.innerHTML = itemRenderer(item);
                    list.appendChild(li);
                });
            };

            renderList('skills', data.skills, skill => skill);

            const experienceContainer = document.getElementById('experience');
            data.experience.forEach(job => {
                const jobDiv = document.createElement('div');
                jobDiv.classList.add('experience');
                jobDiv.innerHTML = `
                    <h3 class="job-title">${job.jobTitle}</h3>
                    <p class="company">${job.company}</p>
                    <p class="job-date">${job.jobDate}</p>
                    <ul>
                        ${job.details.map(detail => `<li>${detail}</li>`).join('')}
                    </ul>
                `;
                experienceContainer.appendChild(jobDiv);
            });

            renderList('education', data.education, edu => `<strong>${edu.degree}</strong>, ${edu.institution} (${edu.years})`);
            renderList('certifications', data.certifications, cert => cert);

        } catch (error) {
            console.error('Error fetching resume data:', error);
            document.querySelector('.card .content').innerHTML = '<p>Error loading resume data. Please try again later.</p>';
        }
    };

    loadResumeData();
});
