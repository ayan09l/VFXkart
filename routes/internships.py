from flask import Blueprint, render_template, request
from extensions import db
from models import (
    Internship, InternProgram, InternModule, InternTask,
    InternEnrollment, TaskSubmission, InternApplication
)

internship_bp = Blueprint("internships", __name__)


# ═══════════════════════════════════════════
#  LESSON CONTENT BUILDER
# ═══════════════════════════════════════════

def _lesson(concepts, code_title, code_lang, code_body, practice, tip):
    """Build slide-based lesson data for the AI animated player with detailed voice narration."""
    import re
    def _strip(html):
        """Strip HTML tags and entities for voice narration, safe for HTML attributes."""
        t = re.sub(r'<[^>]+>', '', html)
        t = t.replace('&lt;', '').replace('&gt;', '').replace('&amp;', 'and')
        t = t.replace('&quot;', '').replace('"', '').replace("'", '')
        return t

    concepts_html = "".join(f"<li>{c}</li>" for c in concepts)

    # Build detailed narration for concepts slide
    concept_narration = "Let's go through the key concepts. "
    for i, c in enumerate(concepts):
        clean = _strip(c)
        concept_narration += f"Point {i+1}: {clean}. "

    # Build detailed narration for code slide
    code_lines = [l for l in code_body.strip().split('\n') if l.strip()]
    code_narration = f"Now let's write some code. This is {_strip(code_title)}. "
    code_narration += f"We are writing {code_lang}. Let me walk you through it step by step. "
    code_narration += f"This code has {len(code_lines)} lines. Watch as each line appears on screen. "
    # Describe first few meaningful lines
    described = 0
    for line in code_lines:
        clean_line = _strip(line).strip()
        if clean_line and described < 4:
            code_narration += f"We write: {clean_line}. "
            described += 1

    # Build detailed narration for practice slide
    practice_narration = f"Time for practice! Here's your exercise: {_strip(practice)}. Try to complete this on your own before moving to the next module."

    # Build detailed narration for tip slide
    tip_narration = f"And here's a pro tip from the industry: {_strip(tip)}. Remember this when you're building real projects."

    return f"""<div class="ai-slide" data-narration="{concept_narration}">
<h3>🎯 Key Concepts</h3>
<ul>{concepts_html}</ul>
</div>
<div class="ai-slide" data-narration="{code_narration}">
<h3>💻 {code_title}</h3>
<div class="code-anim-block" data-lang="{code_lang}"><pre><code>{code_body}</code></pre></div>
</div>
<div class="ai-slide" data-narration="{practice_narration}">
<h3>🧪 Practice Exercise</h3>
<div class="practice-card"><p>{practice}</p></div>
</div>
<div class="ai-slide" data-narration="{tip_narration}">
<h3>💡 Pro Tip</h3>
<div class="tip-card"><p>{tip}</p></div>
</div>"""


# ═══════════════════════════════════════════
#  SEED DATA
# ═══════════════════════════════════════════

SEED_PROGRAMS = [
    {
        "slug": "web-development",
        "title": "Web Development Internship",
        "domain": "web_dev",
        "tagline": "Build real-world websites from scratch — HTML to full-stack deployment.",
        "description": "Master front-end and back-end web development through interactive AI-powered lessons and hands-on project tasks. Build 3 live projects, deploy them, and earn your certificate.",
        "icon": "fas fa-code",
        "color": "#4F46E5",
        "duration_weeks": 4,
        "price": 999,
        "max_seats": 200,
        "skills_covered": "HTML, CSS, JavaScript, React, Node.js, MongoDB, Git, Deployment",
        "modules": [
            {
                "week_number": 1, "title": "HTML Foundations", "lesson_type": "concept", "duration_minutes": 15,
                "video_url": "https://www.youtube.com/embed/qz0aGYrrlhU",
                "description": "Learn how the web works and write your first HTML page with proper structure.",
                "lesson_content": _lesson(
                    concepts=[
                        "<b>HTML</b> = HyperText Markup Language — the skeleton of every webpage",
                        "Every HTML page has <code>&lt;html&gt;</code>, <code>&lt;head&gt;</code>, and <code>&lt;body&gt;</code>",
                        "<b>Semantic tags</b> like <code>&lt;header&gt;</code>, <code>&lt;nav&gt;</code>, <code>&lt;main&gt;</code>, <code>&lt;footer&gt;</code> help search engines understand your page",
                        "Use <code>&lt;h1&gt;</code> to <code>&lt;h6&gt;</code> for headings — only ONE <code>&lt;h1&gt;</code> per page",
                        "<b>Attributes</b> give extra info: <code>&lt;a href=&quot;url&quot;&gt;</code>, <code>&lt;img src=&quot;path&quot; alt=&quot;desc&quot;&gt;</code>",
                    ],
                    code_title="Your First HTML Page",
                    code_lang="html",
                    code_body="""&lt;!DOCTYPE html&gt;
&lt;html lang="en"&gt;
&lt;head&gt;
  &lt;meta charset="UTF-8"&gt;
  &lt;title&gt;My Portfolio&lt;/title&gt;
&lt;/head&gt;
&lt;body&gt;
  &lt;header&gt;
    &lt;h1&gt;Hi, I'm Rahul 👋&lt;/h1&gt;
    &lt;p&gt;Aspiring Web Developer&lt;/p&gt;
  &lt;/header&gt;
  &lt;main&gt;
    &lt;section id="about"&gt;
      &lt;h2&gt;About Me&lt;/h2&gt;
      &lt;p&gt;B.Tech CSE student who loves building things.&lt;/p&gt;
    &lt;/section&gt;
  &lt;/main&gt;
&lt;/body&gt;
&lt;/html&gt;""",
                    practice="Create a personal HTML page with your name, a short bio, and 3 links to your social profiles. Open it in a browser — no CSS needed yet!",
                    tip="Always write semantic HTML first, then add CSS. Google ranks semantic pages higher in search results."
                )
            },
            {
                "week_number": 1, "title": "CSS & Responsive Design", "lesson_type": "code", "duration_minutes": 20,
                "video_url": "https://www.youtube.com/embed/1PnVor36_40",
                "description": "Style your pages with CSS — colors, layout, Flexbox, Grid, and mobile-first design.",
                "lesson_content": _lesson(
                    concepts=[
                        "<b>CSS Selectors</b>: element, .class, #id, [attribute]",
                        "<b>Box Model</b>: content → padding → border → margin",
                        "<b>Flexbox</b> = 1D layout (row OR column). Use <code>display: flex; justify-content; align-items;</code>",
                        "<b>CSS Grid</b> = 2D layout (rows AND columns). Use <code>display: grid; grid-template-columns;</code>",
                        "<b>Media Queries</b>: <code>@media (max-width: 768px)</code> for mobile responsiveness",
                    ],
                    code_title="Flexbox Navigation Bar",
                    code_lang="css",
                    code_body=""".navbar {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 16px 24px;
  background: #1a1a2e;
  color: white;
}

.nav-links {
  display: flex;
  gap: 20px;
  list-style: none;
}

/* Mobile: stack vertically */
@media (max-width: 768px) {
  .navbar { flex-direction: column; }
  .nav-links { flex-direction: column; }
}""",
                    practice="Style the HTML page you created in Module 1. Add a navigation bar using Flexbox, a hero section, and make it responsive using at least one media query.",
                    tip="Start with mobile-first design (small screen default), then add @media queries for larger screens."
                )
            },
            {
                "week_number": 2, "title": "JavaScript Essentials", "lesson_type": "code", "duration_minutes": 20,
                "video_url": "https://www.youtube.com/embed/W6NZfCO5SIk",
                "description": "Variables, functions, DOM manipulation — make your pages interactive.",
                "lesson_content": _lesson(
                    concepts=[
                        "<b>Variables</b>: use <code>const</code> (default) and <code>let</code> (when reassigning). Never <code>var</code>.",
                        "<b>Functions</b>: <code>const greet = (name) =&gt; `Hello ${name}`;</code>",
                        "<b>DOM</b>: <code>document.querySelector('.btn')</code> to select, <code>.addEventListener('click', fn)</code> to interact",
                        "<b>Arrays</b>: <code>.map()</code>, <code>.filter()</code>, <code>.forEach()</code> — learn these 3 and you're 80% there",
                        "<b>Async/Await</b>: <code>const res = await fetch(url);</code> for API calls",
                    ],
                    code_title="Interactive Todo List",
                    code_lang="javascript",
                    code_body="""const input = document.querySelector('#taskInput');
const list = document.querySelector('#taskList');
const btn = document.querySelector('#addBtn');

btn.addEventListener('click', () => {
  const text = input.value.trim();
  if (!text) return;

  const li = document.createElement('li');
  li.textContent = text;
  li.addEventListener('click', () => li.remove());
  list.appendChild(li);

  input.value = '';
});""",
                    practice="Build a simple todo app: an input field, an 'Add' button, and a list. Clicking a task should delete it. Use only vanilla JavaScript — no frameworks.",
                    tip="Master vanilla JS before learning React. If you understand DOM manipulation, React will feel like magic."
                )
            },
            {
                "week_number": 2, "title": "React.js Fundamentals", "lesson_type": "concept", "duration_minutes": 20,
                "video_url": "https://www.youtube.com/embed/SqcY0GlETPk",
                "description": "Components, state, props, hooks — build dynamic single-page applications.",
                "lesson_content": _lesson(
                    concepts=[
                        "<b>Components</b> = reusable building blocks. Think of them as custom HTML tags.",
                        "<b>JSX</b> = HTML inside JavaScript. <code>return &lt;h1&gt;Hello&lt;/h1&gt;;</code>",
                        "<b>Props</b> = data passed FROM parent TO child. <code>&lt;Card title='Hi' /&gt;</code>",
                        "<b>State</b> = data that CHANGES. <code>const [count, setCount] = useState(0);</code>",
                        "<b>useEffect</b> = run code on mount/update. <code>useEffect(() =&gt; { fetch(...) }, []);</code>",
                    ],
                    code_title="React Counter Component",
                    code_lang="jsx",
                    code_body="""import { useState } from 'react';

function Counter() {
  const [count, setCount] = useState(0);

  return (
    &lt;div className="counter"&gt;
      &lt;h2&gt;Count: {count}&lt;/h2&gt;
      &lt;button onClick={() =&gt; setCount(count + 1)}&gt;
        +1
      &lt;/button&gt;
      &lt;button onClick={() =&gt; setCount(0)}&gt;
        Reset
      &lt;/button&gt;
    &lt;/div&gt;
  );
}

export default Counter;""",
                    practice="Create a React app using `npx create-react-app`. Build a component that fetches and displays 5 random users from the API: jsonplaceholder.typicode.com/users",
                    tip="If your component is getting too big, break it into smaller components. A good rule: one component = one responsibility."
                )
            },
            {
                "week_number": 3, "title": "Node.js & Express Backend", "lesson_type": "code", "duration_minutes": 15,
                "video_url": "https://www.youtube.com/embed/ENrzD9HAZK4",
                "description": "Build REST APIs, handle routing, middleware, and connect frontend to backend.",
                "lesson_content": _lesson(
                    concepts=[
                        "<b>Node.js</b> = JavaScript running on the server (not the browser)",
                        "<b>Express</b> = the most popular Node.js web framework (like Flask for Python)",
                        "<b>REST API</b> = GET (read), POST (create), PUT (update), DELETE (remove)",
                        "<b>Middleware</b> = functions that run BEFORE your route handler: <code>app.use(express.json())</code>",
                        "<b>CORS</b> = Cross-Origin Resource Sharing. Enable it so your frontend can talk to your backend.",
                    ],
                    code_title="Express REST API",
                    code_lang="javascript",
                    code_body="""const express = require('express');
const app = express();
app.use(express.json());

let todos = [
  { id: 1, text: 'Learn Node.js', done: false }
];

app.get('/api/todos', (req, res) => {
  res.json(todos);
});

app.post('/api/todos', (req, res) => {
  const todo = {
    id: Date.now(),
    text: req.body.text,
    done: false
  };
  todos.push(todo);
  res.status(201).json(todo);
});

app.listen(3000, () => {
  console.log('Server running on port 3000');
});""",
                    practice="Build a REST API for a 'Notes' app. Implement GET /api/notes (list all), POST /api/notes (create), DELETE /api/notes/:id (delete). Test with Postman.",
                    tip="Always return proper HTTP status codes: 200 (OK), 201 (Created), 404 (Not Found), 500 (Server Error)."
                )
            },
            {
                "week_number": 3, "title": "MongoDB & Data Modeling", "lesson_type": "code", "duration_minutes": 15,
                "video_url": "https://www.youtube.com/embed/ofme2o29ngU",
                "description": "Store data permanently with MongoDB — schemas, CRUD operations, and queries.",
                "lesson_content": _lesson(
                    concepts=[
                        "<b>MongoDB</b> = NoSQL database. Stores data as JSON-like documents (not tables).",
                        "<b>Mongoose</b> = ODM (Object Document Mapper) for MongoDB — like SQLAlchemy for Python.",
                        "<b>Schema</b> = defines the shape of your data: fields, types, required.",
                        "<b>CRUD</b>: <code>.create()</code>, <code>.find()</code>, <code>.findByIdAndUpdate()</code>, <code>.findByIdAndDelete()</code>",
                        "<b>Connection</b>: <code>mongoose.connect('mongodb://localhost:27017/mydb')</code>",
                    ],
                    code_title="Mongoose Schema & CRUD",
                    code_lang="javascript",
                    code_body="""const mongoose = require('mongoose');

// Define schema
const noteSchema = new mongoose.Schema({
  title: { type: String, required: true },
  body: String,
  createdAt: { type: Date, default: Date.now }
});

const Note = mongoose.model('Note', noteSchema);

// CREATE
const newNote = await Note.create({
  title: 'First Note',
  body: 'Learning MongoDB!'
});

// READ
const allNotes = await Note.find();
const one = await Note.findById(id);

// UPDATE
await Note.findByIdAndUpdate(id, { title: 'Updated' });

// DELETE
await Note.findByIdAndDelete(id);""",
                    practice="Connect your Express API to MongoDB using Mongoose. Replace the in-memory array with a real database. All notes should persist across server restarts.",
                    tip="Use MongoDB Atlas (free tier) for cloud-hosted MongoDB. No local installation needed."
                )
            },
            {
                "week_number": 4, "title": "Auth & Security", "lesson_type": "concept", "duration_minutes": 15,
                "video_url": "https://www.youtube.com/embed/mbsmsi7l3r4",
                "description": "JWT tokens, password hashing, OAuth — protect your users and routes.",
                "lesson_content": _lesson(
                    concepts=[
                        "<b>Never store plain text passwords!</b> Use <code>bcrypt.hash(password, 10)</code>",
                        "<b>JWT</b> (JSON Web Token) = a signed token proving user identity. <code>jwt.sign({ userId: user.id }, SECRET)</code>",
                        "<b>Auth flow</b>: Register → Hash password → Store in DB → Login → Compare hash → Return JWT",
                        "<b>Protected routes</b>: Check JWT in the <code>Authorization</code> header before allowing access",
                        "<b>OAuth</b> = 'Login with Google/GitHub' — uses a third-party to verify identity",
                    ],
                    code_title="JWT Authentication",
                    code_lang="javascript",
                    code_body="""const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const SECRET = 'your-secret-key';

// REGISTER
app.post('/register', async (req, res) => {
  const hash = await bcrypt.hash(req.body.password, 10);
  const user = await User.create({
    email: req.body.email,
    password: hash
  });
  res.status(201).json({ message: 'Registered!' });
});

// LOGIN
app.post('/login', async (req, res) => {
  const user = await User.findOne({ email: req.body.email });
  if (!user) return res.status(404).json({ error: 'User not found' });

  const match = await bcrypt.compare(req.body.password, user.password);
  if (!match) return res.status(401).json({ error: 'Wrong password' });

  const token = jwt.sign({ id: user._id }, SECRET);
  res.json({ token });
});""",
                    practice="Add authentication to your Notes API: Register, Login, and protect the /api/notes routes so only logged-in users can create notes. Use JWT.",
                    tip="Store JWT in httpOnly cookies (not localStorage) for production apps — it prevents XSS attacks."
                )
            },
            {
                "week_number": 4, "title": "Git & Deployment", "lesson_type": "practice", "duration_minutes": 10,
                "video_url": "https://www.youtube.com/embed/RGOj5yH7evk",
                "description": "Version control with Git and deploy your app to the world.",
                "lesson_content": _lesson(
                    concepts=[
                        "<b>Git</b> = version control. Tracks every change you make to your code.",
                        "<b>Essential commands</b>: <code>git init</code>, <code>git add .</code>, <code>git commit -m 'msg'</code>, <code>git push</code>",
                        "<b>Branches</b>: <code>git checkout -b feature/login</code> — work on features without breaking main code",
                        "<b>GitHub</b> = host your code online + act as your portfolio",
                        "<b>Deploy</b>: Frontend → Vercel/Netlify (free). Backend → Render/Railway (free tier).",
                    ],
                    code_title="Deploy Workflow",
                    code_lang="bash",
                    code_body="""# Initialize and push to GitHub
git init
git add .
git commit -m "Initial commit"
git remote add origin https://github.com/you/project.git
git push -u origin main

# Deploy frontend to Vercel
npm i -g vercel
vercel --prod

# Deploy backend to Render
# 1. Push to GitHub
# 2. Go to render.com → New Web Service
# 3. Connect your repo → Deploy!""",
                    practice="Push your Notes app to GitHub. Deploy the frontend to Vercel and the backend to Render. Share the live URL — this is your first deployed full-stack app!",
                    tip="Add a README.md with screenshots, tech stack, and setup instructions. Recruiters check your GitHub README first."
                )
            },
        ],
        "tasks": [
            {"order": 1, "title": "Build a Portfolio Website", "description": "Create a personal portfolio with Home, About, Projects, and Contact sections. Must be fully responsive.", "requirements": "Deploy on Vercel or Netlify. Submit the live URL and GitHub repo link.", "submission_type": "url", "max_score": 100, "deadline_days": 7},
            {"order": 2, "title": "Build a To-Do App with React", "description": "Create a CRUD to-do application using React.js with state management. Include add, edit, delete, and filter features.", "requirements": "Submit GitHub repository link with README. App must be functional.", "submission_type": "github_link", "max_score": 100, "deadline_days": 7},
            {"order": 3, "title": "Full-Stack Blog Platform", "description": "Build a blog app with Node.js + MongoDB backend and React frontend. Include user auth (login/signup), create/edit/delete posts.", "requirements": "Submit GitHub repo + deployed URL. Must have working authentication.", "submission_type": "github_link", "max_score": 100, "deadline_days": 14},
        ]
    },
    {
        "slug": "python-programming",
        "title": "Python Programming Internship",
        "domain": "python",
        "tagline": "From zero to Python pro — build automation tools and data scripts.",
        "description": "Learn Python fundamentals, data handling, API development, and automation through interactive lessons. Complete 3 coding challenges to earn your certificate.",
        "icon": "fab fa-python",
        "color": "#059669",
        "duration_weeks": 4,
        "price": 799,
        "max_seats": 200,
        "skills_covered": "Python, Flask, Pandas, APIs, Automation, Git",
        "modules": [
            {
                "week_number": 1, "title": "Python Basics & Data Types", "lesson_type": "concept", "duration_minutes": 15,
                "video_url": "https://www.youtube.com/embed/kqtD5dpn9C8",
                "description": "Variables, loops, functions, and OOP fundamentals.",
                "lesson_content": _lesson(
                    concepts=[
                        "<b>Python</b> is dynamically typed: <code>x = 10</code> (no need to declare type)",
                        "<b>Data types</b>: int, float, str, list, dict,吐ple, set, bool",
                        "<b>Lists</b>: <code>names = ['Rahul', 'Priya']</code> — ordered, mutable",
                        "<b>Dictionaries</b>: <code>student = {'name': 'Rahul', 'age': 20}</code> — key-value pairs",
                        "<b>Functions</b>: <code>def greet(name): return f'Hello {name}'</code>",
                    ],
                    code_title="Python Fundamentals",
                    code_lang="python",
                    code_body="""# Variables & types
name = "Rahul"
age = 20
skills = ["Python", "Flask", "SQL"]

# Functions
def introduce(name, skills):
    skill_str = ", ".join(skills)
    return f"Hi, I'm {name}. I know {skill_str}."

print(introduce(name, skills))

# List comprehension
even = [x for x in range(20) if x % 2 == 0]

# Dictionary
student = {
    "name": name,
    "age": age,
    "gpa": 8.5
}""",
                    practice="Write a function `analyze_marks(marks_list)` that takes a list of marks and returns a dict with keys: total, average, highest, lowest, pass_count (>=40).",
                    tip="Use f-strings for formatting: f'Score: {score}' — they're faster and cleaner than .format() or %."
                )
            },
            {
                "week_number": 2, "title": "File Handling & Web Scraping", "lesson_type": "code", "duration_minutes": 15,
                "video_url": "https://www.youtube.com/embed/ng2o98k983k",
                "description": "Read/write files, work with CSV/JSON, and scrape websites.",
                "lesson_content": _lesson(
                    concepts=[
                        "<b>File modes</b>: 'r' (read), 'w' (write), 'a' (append). Always use <code>with open()</code>",
                        "<b>CSV</b>: <code>import csv</code> or use <code>pandas.read_csv()</code> for bigger files",
                        "<b>JSON</b>: <code>json.load(file)</code> to read, <code>json.dump(data, file)</code> to write",
                        "<b>requests</b>: <code>requests.get(url).json()</code> to fetch API data",
                        "<b>BeautifulSoup</b>: <code>soup.select('.price')</code> to extract HTML elements",
                    ],
                    code_title="Web Scraper",
                    code_lang="python",
                    code_body="""import requests
from bs4 import BeautifulSoup
import csv

url = "https://example.com/products"
page = requests.get(url)
soup = BeautifulSoup(page.content, "html.parser")

products = []
for item in soup.select(".product-card"):
    name = item.select_one(".title").text.strip()
    price = item.select_one(".price").text.strip()
    products.append({"name": name, "price": price})

# Save to CSV
with open("products.csv", "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=["name", "price"])
    writer.writeheader()
    writer.writerows(products)

print(f"Scraped {len(products)} products!")""",
                    practice="Scrape the top 10 trending repositories from GitHub's trending page. Save the repo name, stars, and language to a CSV file.",
                    tip="Always add `time.sleep(1)` between requests when scraping — be polite to servers."
                )
            },
            {
                "week_number": 3, "title": "Flask Web Framework", "lesson_type": "code", "duration_minutes": 15,
                "video_url": "https://www.youtube.com/embed/Z1RJmh_OqeA",
                "description": "Build web apps with Flask — routing, templates, forms, and databases.",
                "lesson_content": _lesson(
                    concepts=[
                        "<b>Flask</b> = lightweight Python web framework (powers VFXKart!)",
                        "<b>Routes</b>: <code>@app.route('/about')</code> → serves a page",
                        "<b>Templates</b>: Jinja2 with <code>{{ variable }}</code> and <code>{% for item in list %}</code>",
                        "<b>Forms</b>: <code>request.form['name']</code> to get form data",
                        "<b>SQLAlchemy</b>: ORM to interact with databases without writing raw SQL",
                    ],
                    code_title="Flask App",
                    code_lang="python",
                    code_body="""from flask import Flask, render_template, request, jsonify

app = Flask(__name__)

tasks = []

@app.route('/')
def home():
    return render_template('index.html', tasks=tasks)

@app.route('/api/tasks', methods=['GET'])
def get_tasks():
    return jsonify(tasks)

@app.route('/api/tasks', methods=['POST'])
def add_task():
    data = request.json
    task = {'id': len(tasks)+1, 'text': data['text'], 'done': False}
    tasks.append(task)
    return jsonify(task), 201

if __name__ == '__main__':
    app.run(debug=True)""",
                    practice="Build a Flask 'Student Directory' app: Add students (name, roll, branch), list all, delete by ID. Use HTML forms + Jinja templates.",
                    tip="Use Flask Blueprints to organize routes when your app grows beyond 5-6 routes."
                )
            },
            {
                "week_number": 4, "title": "Data Analysis with Pandas", "lesson_type": "practice", "duration_minutes": 15,
                "video_url": "https://www.youtube.com/embed/vmEHCJofslg",
                "description": "DataFrames, CSV processing, visualization with Matplotlib.",
                "lesson_content": _lesson(
                    concepts=[
                        "<b>Pandas</b> = the #1 library for data analysis in Python",
                        "<b>DataFrame</b> = a table of data: <code>df = pd.read_csv('data.csv')</code>",
                        "<b>Key methods</b>: <code>.head()</code>, <code>.describe()</code>, <code>.groupby()</code>, <code>.value_counts()</code>",
                        "<b>Filtering</b>: <code>df[df['age'] > 20]</code> — like SQL WHERE clause",
                        "<b>Visualization</b>: <code>df.plot(kind='bar')</code> or use <code>matplotlib</code> / <code>seaborn</code>",
                    ],
                    code_title="Analyzing Student Data",
                    code_lang="python",
                    code_body="""import pandas as pd
import matplotlib.pyplot as plt

# Load data
df = pd.read_csv("students.csv")

# Quick overview
print(df.describe())

# Average marks by branch
branch_avg = df.groupby('branch')['marks'].mean()
print(branch_avg)

# Students who scored above 80
toppers = df[df['marks'] >= 80]
print(f"Toppers: {len(toppers)}")

# Visualization
branch_avg.plot(kind='bar', color='#4F46E5')
plt.title('Average Marks by Branch')
plt.ylabel('Marks')
plt.tight_layout()
plt.savefig('chart.png')
plt.show()""",
                    practice="Download any CSV dataset from Kaggle. Load it with Pandas, find 5 insights (e.g., max, min, average, top category), and create 2 charts.",
                    tip="Use df.info() to check for missing values before analysis. Missing data = wrong results."
                )
            },
        ],
        "tasks": [
            {"order": 1, "title": "Build a CLI Calculator", "description": "Create a command-line calculator with advanced operations (+, -, *, /, power, square root).", "requirements": "Submit Python file via GitHub.", "submission_type": "github_link", "max_score": 100, "deadline_days": 5},
            {"order": 2, "title": "Web Scraper Tool", "description": "Build a web scraper that extracts data from any website and saves to CSV.", "requirements": "Submit GitHub repo with README.", "submission_type": "github_link", "max_score": 100, "deadline_days": 7},
            {"order": 3, "title": "Flask REST API", "description": "Build a RESTful API with Flask for a student management system.", "requirements": "Submit GitHub repo + Postman collection.", "submission_type": "github_link", "max_score": 100, "deadline_days": 10},
        ]
    },
    {
        "slug": "data-science",
        "title": "Data Science Internship",
        "domain": "data_science",
        "tagline": "Analyze real datasets, build ML models, and create dashboards.",
        "description": "Dive into data analysis, visualization, and machine learning. Work with real-world datasets and deploy an interactive dashboard.",
        "icon": "fas fa-chart-bar",
        "color": "#D97706",
        "duration_weeks": 6,
        "price": 1499,
        "max_seats": 100,
        "skills_covered": "Python, Pandas, NumPy, Matplotlib, Scikit-learn, Streamlit",
        "modules": [],
        "tasks": []
    },
    {
        "slug": "ui-ux-design",
        "title": "UI/UX Design Internship",
        "domain": "design",
        "tagline": "Design beautiful, user-centric interfaces for web and mobile.",
        "description": "Learn design thinking, wireframing, prototyping with Figma, and user research. Design 2 complete app interfaces.",
        "icon": "fas fa-palette",
        "color": "#EC4899",
        "duration_weeks": 3,
        "price": 699,
        "max_seats": 150,
        "skills_covered": "Figma, Wireframing, Prototyping, Color Theory, Typography",
        "modules": [],
        "tasks": []
    },
    {
        "slug": "digital-marketing",
        "title": "Digital Marketing Internship",
        "domain": "marketing",
        "tagline": "Learn SEO, social media strategy, and ad campaign management.",
        "description": "Master digital marketing through real campaign execution. Run Google Ads, build social media calendars, and analyze performance.",
        "icon": "fas fa-bullhorn",
        "color": "#EF4444",
        "duration_weeks": 3,
        "price": 499,
        "max_seats": 300,
        "skills_covered": "SEO, Google Ads, Social Media, Analytics, Content Writing",
        "modules": [],
        "tasks": []
    },
    {
        "slug": "ai-ml-basics",
        "title": "AI & Machine Learning Internship",
        "domain": "ai_ml",
        "tagline": "Build and deploy your first machine learning model.",
        "description": "Learn supervised/unsupervised learning, neural networks, NLP basics, and deploy an ML model to production.",
        "icon": "fas fa-brain",
        "color": "#7C3AED",
        "duration_weeks": 4,
        "price": 1299,
        "max_seats": 100,
        "skills_covered": "Python, TensorFlow, Scikit-learn, NLP, Model Deployment",
        "modules": [],
        "tasks": []
    },
]


def seed_intern_programs():
    """Seed the database with initial internship programs if empty."""
    if InternProgram.query.count() > 0:
        return

    for p_data in SEED_PROGRAMS:
        prog = InternProgram(
            slug=p_data["slug"],
            title=p_data["title"],
            domain=p_data["domain"],
            tagline=p_data.get("tagline", ""),
            description=p_data.get("description", ""),
            icon=p_data.get("icon", "fas fa-code"),
            color=p_data.get("color", "#4F46E5"),
            duration_weeks=p_data.get("duration_weeks", 4),
            price=p_data.get("price", 999),
            max_seats=p_data.get("max_seats", 100),
            skills_covered=p_data.get("skills_covered", ""),
        )
        db.session.add(prog)
        db.session.flush()

        for m in p_data.get("modules", []):
            db.session.add(InternModule(
                program_id=prog.id,
                week_number=m["week_number"],
                title=m["title"],
                description=m.get("description", ""),
                video_url=m.get("video_url", ""),
                lesson_content=m.get("lesson_content", ""),
                lesson_type=m.get("lesson_type", "concept"),
                duration_minutes=m.get("duration_minutes", 15),
            ))

        for t in p_data.get("tasks", []):
            db.session.add(InternTask(
                program_id=prog.id,
                order=t["order"],
                title=t["title"],
                description=t.get("description", ""),
                requirements=t.get("requirements", ""),
                submission_type=t.get("submission_type", "github_link"),
                max_score=t.get("max_score", 100),
                deadline_days=t.get("deadline_days", 7),
            ))

    db.session.commit()
    print("✅ Seeded internship programs!")


# ═══════════════════════════════════════════
#  ROUTES
# ═══════════════════════════════════════════

@internship_bp.route("/internships")
def internships():
    """Legacy: external internship listings."""
    q = request.args.get("q", "")
    category = request.args.get("category")
    location = request.args.get("location")
    paid = request.args.get("paid")

    query = Internship.query
    if q:
        query = query.filter(Internship.title.ilike(f"%{q}%") | Internship.company.ilike(f"%{q}%"))
    if category and category != "All":
        query = query.filter_by(category=category)
    if location and location != "All":
        query = query.filter_by(location=location)
    if paid == "paid":
        query = query.filter(Internship.stipend != "Unpaid")

    internships_list = query.order_by(Internship.created_at.desc()).all()
    return render_template("internships.html", internships=internships_list)


@internship_bp.route("/programs")
def programs_landing():
    """Landing page for the internship programs."""
    programs = InternProgram.query.filter_by(is_active=True).all()
    return render_template("intern_landing.html", programs=programs)


@internship_bp.route("/programs/<slug>")
def program_detail(slug):
    """Single program page with lesson modules, tasks, and enroll button."""
    program = InternProgram.query.filter_by(slug=slug).first_or_404()
    weeks = {}
    for m in program.modules:
        weeks.setdefault(m.week_number, []).append(m)
    return render_template("intern_program.html", program=program, weeks=weeks)


@internship_bp.route("/programs/<slug>/apply", methods=["GET", "POST"])
def apply_program(slug):
    """Application form for the direct task + stipend model."""
    from flask import flash, redirect, url_for
    from models import InternProgram, InternApplication
    program = InternProgram.query.filter_by(slug=slug).first_or_404()
    
    if request.method == "POST":
        app = InternApplication(
            program_id=program.id,
            full_name=request.form.get("full_name"),
            email=request.form.get("email"),
            phone=request.form.get("phone"),
            college=request.form.get("college"),
            year_of_study=request.form.get("year_of_study"),
            branch=request.form.get("branch"),
            github_url=request.form.get("github_url"),
            linkedin_url=request.form.get("linkedin_url"),
            portfolio_url=request.form.get("portfolio_url"),
            skills=request.form.get("skills"),
            why_apply=request.form.get("why_apply"),
            experience=request.form.get("experience"),
            availability=request.form.get("availability"),
            status="pending"
        )
        db.session.add(app)
        db.session.commit()

        flash("Application submitted successfully!", "success")
        return render_template("application_success.html", program=program)

    return render_template("intern_apply.html", program=program)