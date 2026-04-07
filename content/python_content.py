# -*- coding: utf-8 -*-
"""
VFXKart — Python Learning Content
Each topic has 6 unique layers that NO other platform provides:
  1. 3AM Analogy
  2. Broken Code First (Failure-First)
  3. Real Product Link
  4. Common Trap
  5. Viva Ready
  6. Mini-Build Challenge
"""

PYTHON_CHAPTERS = [
    {"id": "basics", "title": "Python Basics", "icon": ""},
    {"id": "control", "title": "Control Flow", "icon": ""},
    {"id": "data_structures", "title": "Data Structures", "icon": ""},
    {"id": "functions", "title": "Functions", "icon": ""},
    {"id": "oop", "title": "Object-Oriented Programming", "icon": ""},
    {"id": "advanced", "title": "Advanced Python", "icon": ""},
]

PYTHON_TOPICS = {
    # ═══════════════════════════════════════════
    # CHAPTER: BASICS
    # ═══════════════════════════════════════════

    "introduction": {
        "title": "Python Introduction",
        "chapter": "basics",
        "order": 1,

        "analogy": "Python is like English among programming languages — while C++ and Java are like writing in formal Latin or Sanskrit with strict grammar rules, Python lets you express the same ideas in simple, everyday English. That's why beginners love it and companies like Google use it for their biggest projects.",

        "explanation": """
<h3>What is Python?</h3>
<p>Python is a <strong>high-level, interpreted programming language</strong> created by <em>Guido van Rossum</em> in 1991. It's designed to be easy to read and write — almost like writing pseudocode.</p>

<h3>Why Python?</h3>
<ul>
    <li><strong>Easy to learn</strong> — Clean syntax, no semicolons or curly braces needed</li>
    <li><strong>Versatile</strong> — Web development, AI/ML, Data Science, Automation, Game Dev</li>
    <li><strong>Huge community</strong> — Millions of developers, thousands of libraries</li>
    <li><strong>High demand</strong> — One of the most in-demand skills in the job market</li>
</ul>

<h3>Your First Python Program</h3>
<p>In C or Java, printing "Hello" takes 5-10 lines. In Python, it takes <strong>one</strong>:</p>
""",

        "code": 'print("Hello, VFXKart! 🚀")\nprint("Welcome to Python")\nprint(2 + 3)\nprint("Python is", 35, "years old")',
        "output": 'Hello, VFXKart! 🚀\nWelcome to Python\n5\nPython is 35 years old',

        "broken_code": '# 🔍 Find the bug!\nPrint("Hello World")',
        "broken_hint": "Python is case-sensitive. Look carefully at the function name.",
        "broken_fix": '# ✅ Fixed! print() is lowercase\nprint("Hello World")',

        "real_product": "YouTube's backend was originally built with Python. When you search for a video, Python code processes your query, fetches results from the database, and sends them back to your screen — all in milliseconds.",

        "trap": "Writing <code>Print()</code> instead of <code>print()</code>. Python is CASE-SENSITIVE — <code>Print</code>, <code>PRINT</code>, and <code>print</code> are three completely different things. Only <code>print</code> (all lowercase) is the built-in function.",

        "viva_q": "What makes Python an interpreted language? How is it different from compiled languages like C?",
        "viva_a": "Python is interpreted because the code is executed line-by-line at runtime by the Python interpreter, without being converted to machine code beforehand. In C, the entire code is first compiled into an executable binary, then run. This makes Python slower but much easier to debug and develop with.",

        "mini_build": "Build a Personal Introduction Printer",
        "mini_build_desc": "Create a program that prints your complete introduction — name, college, branch, year, and a fun fact about you.",
        "mini_build_code": "# My Personal Introduction\nprint('=' * 40)\nprint('   MY INTRODUCTION')\nprint('=' * 40)\nprint('Name    : Arjun Sharma')\nprint('College : VIT Vellore')\nprint('Branch  : Computer Science')\nprint('Year    : 2nd Year')\nprint('Fun Fact: I can solve a Rubiks cube!')\nprint('=' * 40)",

        "mission": {
            "company": "Google",
            "company_icon": "🔍",
            "level": "Intern",
            "scenario": "You just joined Google as a Software Engineering Intern on the Search Quality team. Your manager walks over on Day 1 and says: 'Hey! Before you touch any real code, I need to see if you can write basic Python scripts. We use Python for almost everything here — from testing search algorithms to automating server checks.'",
            "task": "Write a Python script that prints Google's daily server status report. Print the company name, today's date, number of servers running, and a welcome message for new interns.",
            "steps": [
                "Print the company name: 'Google Search Quality Team'",
                "Print a separator line using the * operator on a string",
                "Print server count: 48,291 servers active",
                "Print uptime: 99.97%",
                "Print a welcome message with your name",
            ],
            "skills": "print(), strings, numbers, string repetition",
            "solution": "# Google Intern — Day 1 Task\nprint('GOOGLE SEARCH QUALITY TEAM')\nprint('=' * 40)\nprint('Daily Server Status Report')\nprint('─' * 40)\nprint('Active Servers : 48,291')\nprint('Uptime         : 99.97%')\nprint('Region         : Asia-Pacific')\nprint('Status         : ✅ All Systems Normal')\nprint('─' * 40)\nprint('Welcome aboard, Intern! 🚀')\nprint('Your journey at Google starts now.')",
            "solution_output": "GOOGLE SEARCH QUALITY TEAM\n========================================\nDaily Server Status Report\n────────────────────────────────────────\nActive Servers : 48,291\nUptime         : 99.97%\nRegion         : Asia-Pacific\nStatus         : ✅ All Systems Normal\n────────────────────────────────────────\nWelcome aboard, Intern! 🚀\nYour journey at Google starts now.",
            "takeaway": "Every engineer at Google writes scripts like this daily. print() is not just a beginner thing — it's how you output logs, debug info, and status reports in production systems.",
        },
    },

    "variables": {
        "title": "Variables & Data Types",
        "chapter": "basics",
        "order": 2,

        "analogy": "A variable is like a <strong>labeled jar</strong> in your kitchen. The jar is the variable, the label is the name, and whatever you put inside (rice, sugar, water) is the value. You can empty the jar and refill it anytime — just like you can reassign a variable.",

        "explanation": """
<h3>What is a Variable?</h3>
<p>A variable is a <strong>named container</strong> that stores data. In Python, you create a variable simply by assigning a value — no need to declare its type.</p>

<h3>Python Data Types</h3>
<table class="content-table">
    <tr><th>Type</th><th>Example</th><th>Description</th></tr>
    <tr><td><code>str</code></td><td><code>"Hello"</code></td><td>Text (string)</td></tr>
    <tr><td><code>int</code></td><td><code>42</code></td><td>Whole number</td></tr>
    <tr><td><code>float</code></td><td><code>3.14</code></td><td>Decimal number</td></tr>
    <tr><td><code>bool</code></td><td><code>True / False</code></td><td>Boolean (yes/no)</td></tr>
</table>

<h3>Variable Naming Rules</h3>
<ul>
    <li>Must start with a letter or underscore (<code>_</code>)</li>
    <li>Cannot start with a number</li>
    <li>Can only contain letters, numbers, and underscores</li>
    <li>Case-sensitive (<code>name</code> ≠ <code>Name</code> ≠ <code>NAME</code>)</li>
</ul>
""",

        "code": '# Creating variables (no type declaration needed!)\nname = "VFXKart"\nage = 21\npi = 3.14159\nis_student = True\n\n# Check types\nprint(name, "→", type(name))\nprint(age, "→", type(age))\nprint(pi, "→", type(pi))\nprint(is_student, "→", type(is_student))\n\n# Reassign — Python doesn\'t care about type change\nage = "twenty-one"  # was int, now str\nprint("age is now:", age, type(age))',
        "output": "VFXKart → <class 'str'>\n21 → <class 'int'>\n3.14159 → <class 'float'>\nTrue → <class 'bool'>\nage is now: twenty-one <class 'str'>",

        "broken_code": '# 🔍 What\'s WRONG here? (2 bugs!)\n2fast = "Vin Diesel"\nmy name = "Arjun"\nprint(2fast)\nprint(my name)',
        "broken_hint": "Variable names cannot start with a number, and cannot have spaces.",
        "broken_fix": '# ✅ Fixed!\nfast2 = "Vin Diesel"     # number at END is fine\nmy_name = "Arjun"        # use underscore, not space\nprint(fast2)\nprint(my_name)',

        "real_product": "In Zomato, when you open a restaurant page, variables store the restaurant name, rating (float), number of reviews (int), is_open (bool), and delivery time (int). Every piece of data on that screen is sitting in a variable somewhere in their backend.",

        "trap": "Writing <code>Name</code> and <code>name</code> thinking they're the same variable. They're NOT — Python is case-sensitive! This causes bugs where your code 'forgets' a value because you're accidentally reading from the wrong variable.",

        "viva_q": "Is Python statically typed or dynamically typed? What's the difference?",
        "viva_a": "Python is dynamically typed — the type of a variable is determined at runtime when you assign a value, not at compile time. You don't need to declare types like <code>int x = 5</code> in C. You just write <code>x = 5</code> and Python figures out it's an integer. You can even change the type later: <code>x = 'hello'</code> makes x a string now.",

        "mini_build": "Student ID Card Generator",
        "mini_build_desc": "Create variables for a student's complete profile and print a formatted ID card.",
        "mini_build_code": "# Student ID Card Generator\nname = 'Priya Mehta'\nroll_no = '22BCS1456'\nbranch = 'Computer Science'\nyear = 2\ncgpa = 8.7\nis_hosteler = True\n\nprint('=' * 36)\nprint('    STUDENT ID CARD')\nprint('=' * 36)\nprint(f'  Name    : {name}')\nprint(f'  Roll    : {roll_no}')\nprint(f'  Branch  : {branch}')\nprint(f'  Year    : {year}')\nprint(f'  CGPA    : {cgpa}')\nhostel_status = 'Yes' if is_hosteler else 'No'\nprint(f'  Hostel  : {hostel_status}')\nprint('=' * 36)",

        "mission": {
            "company": "Flipkart",
            "company_icon": "🛒",
            "level": "Junior Dev",
            "scenario": "You are hired as a Junior Backend Developer at Flipkart. The Product Catalog team needs someone to set up the data model for a new product listing. Your tech lead says: 'We store every product's info in variables — name, price, rating, stock count, whether it's on sale. Get this right because the entire checkout flow depends on this data.'",
            "task": "Create variables to store a complete Flipkart product listing. Use the correct data types — string for name, float for price, int for stock, bool for availability. Then print a formatted product card.",
            "steps": [
                "Create a string variable for the product name",
                "Create a float variable for the price (₹)",
                "Create an int variable for stock quantity",
                "Create a bool variable for is_on_sale",
                "Create a float for the discount percentage",
                "Print a formatted product card showing all details",
            ],
            "skills": "variables, str, int, float, bool, f-strings, type()",
            "solution": "# Flipkart Product Listing\nproduct_name = 'boAt Rockerz 450 Headphones'\nprice = 1499.00\noriginal_price = 2999.00\nstock = 347\nis_on_sale = True\nrating = 4.3\nreviews = 28456\ncategory = 'Electronics'\n\n# Calculate discount\ndiscount = round((1 - price/original_price) * 100)\n\nprint('🛒 FLIPKART PRODUCT CARD')\nprint('═' * 40)\nprint(f'Product  : {product_name}')\nprint(f'Category : {category}')\nprint(f'Price    : ₹{price} (was ₹{original_price})')\nprint(f'Discount : {discount}% OFF')\nprint(f'Rating   : ⭐ {rating} ({reviews} reviews)')\nprint(f'Stock    : {stock} units left')\nprint(f'On Sale  : {\"YES 🔥\" if is_on_sale else \"No\"}')\nprint(f'═' * 40)\nprint(f'Types: name={type(product_name).__name__}, price={type(price).__name__}, stock={type(stock).__name__}, sale={type(is_on_sale).__name__}')",
            "solution_output": "🛒 FLIPKART PRODUCT CARD\n════════════════════════════════════════\nProduct  : boAt Rockerz 450 Headphones\nCategory : Electronics\nPrice    : ₹1499.0 (was ₹2999.0)\nDiscount : 50% OFF\nRating   : ⭐ 4.3 (28456 reviews)\nStock    : 347 units left\nOn Sale  : YES 🔥\n════════════════════════════════════════\nTypes: name=str, price=float, stock=int, sale=bool",
            "takeaway": "At Flipkart, every single product page you see is powered by variables like these stored in a database. Getting the data types right (float for price, not int!) is critical — a wrong type can break the checkout and lose crores in revenue.",
        },
    },

    "strings": {
        "title": "Strings",
        "chapter": "basics",
        "order": 3,

        "analogy": "A string is like a <strong>necklace of beads</strong> — each bead is one character. You can count the beads (length), pick the 3rd bead (indexing), cut a section of beads (slicing), or join two necklaces together (concatenation). But you can't change a single bead without making a new necklace — that's why strings are immutable.",

        "explanation": """
<h3>What is a String?</h3>
<p>A string is a <strong>sequence of characters</strong> enclosed in quotes. You can use single quotes <code>'hello'</code>, double quotes <code>"hello"</code>, or triple quotes for multi-line strings.</p>

<h3>String Operations</h3>
<table class="content-table">
    <tr><th>Operation</th><th>Syntax</th><th>Example</th></tr>
    <tr><td>Concatenation</td><td><code>+</code></td><td><code>"Hello" + " World"</code></td></tr>
    <tr><td>Repetition</td><td><code>*</code></td><td><code>"Ha" * 3</code> → <code>"HaHaHa"</code></td></tr>
    <tr><td>Indexing</td><td><code>[i]</code></td><td><code>"Python"[0]</code> → <code>"P"</code></td></tr>
    <tr><td>Slicing</td><td><code>[start:end]</code></td><td><code>"Python"[0:3]</code> → <code>"Pyt"</code></td></tr>
    <tr><td>Length</td><td><code>len()</code></td><td><code>len("Python")</code> → <code>6</code></td></tr>
</table>

<h3>f-Strings (Formatted Strings)</h3>
<p>The most modern and powerful way to insert variables into strings:</p>
""",

        "code": '# String basics\nname = "VFXKart"\nprint(name[0])      # First character\nprint(name[-1])     # Last character\nprint(name[0:3])    # Slicing\nprint(len(name))    # Length\n\n# f-String formatting (Python 3.6+)\nuser = "Arjun"\nage = 21\nprint(f"Hi, I am {user} and I am {age} years old")\n\n# Useful string methods\nmessage = "  hello world  "\nprint(message.strip())       # Remove spaces\nprint(message.upper())       # UPPERCASE\nprint(message.replace("hello", "hey"))\nprint("world" in message)    # Check if exists',
        "output": 'V\nt\nVFX\n7\nHi, I am Arjun and I am 21 years old\nhello world\n  HELLO WORLD  \n  hey world  \nTrue',

        "broken_code": '# 🔍 Find the bug!\nname = "Python"\nname[0] = "J"  # Try to change P to J\nprint(name)',
        "broken_hint": "Strings in Python are immutable — you cannot change individual characters.",
        "broken_fix": '# ✅ Fixed! Create a NEW string instead\nname = "Python"\nname = "J" + name[1:]  # Slice off P, add J\nprint(name)  # Jython',

        "real_product": "When you type a message on WhatsApp, your text is a string. The app uses string methods to detect URLs (and make them clickable), find @mentions, apply bold/italic formatting (*bold*), and even check for banned words — all using string operations you're learning right now.",

        "trap": "Trying to modify a string character with <code>name[0] = 'X'</code>. This CRASHES because strings are <strong>immutable</strong> in Python. You must create a new string instead. This is the #1 error students make with strings.",

        "viva_q": "What does it mean that strings are immutable in Python? Can you give an example?",
        "viva_a": "Immutable means once a string is created, its individual characters cannot be changed in-place. For example, <code>s = 'Hello'</code> then <code>s[0] = 'J'</code> will raise a TypeError. To 'change' a string, you must create a new one: <code>s = 'J' + s[1:]</code>. This is a design choice for memory optimization and thread safety.",

        "mini_build": "WhatsApp Message Formatter",
        "mini_build_desc": "Build a program that takes a message and applies transformations — uppercase, word count, character count, and censors a banned word.",
        "mini_build_code": '# 🔨 WhatsApp Message Formatter\nmessage = "Hey bro, the exam was damn easy lol"\n\nprint("📱 MESSAGE ANALYZER")\nprint("─" * 40)\nprint(f"Original : {message}")\nprint(f"UPPERCASE: {message.upper()}")\nprint(f"lowercase: {message.lower()}")\nprint(f"Words    : {len(message.split())}")\nprint(f"Chars    : {len(message)}")\nprint(f"Has \'exam\': {\'exam\' in message}")\n\n# Censor a word\ncensored = message.replace("damn", "d***")\nprint(f"Censored : {censored}")\n\n# Reverse the message\nprint(f"Reversed : {message[::-1]}")',

        "mission": {
            "company": "Instagram (Meta)",
            "company_icon": "📸",
            "level": "SDE-1",
            "scenario": "You just joined Instagram's Content Moderation team at Meta. Millions of captions and comments are posted every minute. Your team lead says: 'We need a Python script that can process user captions — extract hashtags, check for banned words, count mentions, and format display text. This runs on every single post.'",
            "task": "Build a caption processing system that takes an Instagram caption string, extracts all #hashtags, counts @mentions, checks for a banned word, and formats the display.",
            "steps": [
                "Take a sample caption with hashtags and mentions",
                "Extract all words starting with # (hashtags)",
                "Count all words starting with @ (mentions)",
                "Check if any banned word exists using 'in'",
                "Create a truncated preview (first 50 chars + '...')",
                "Print a formatted moderation report",
            ],
            "skills": "string slicing, .split(), .startswith(), len(), in, f-strings",
            "solution": "# Instagram Caption Processor\ncaption = 'Just vibing at the beach 🌊 @priya_m @arjun.dev #sunset #beachlife #nofilter Love this ugly weather tho'\n\n# Extract hashtags\nwords = caption.split()\nhashtags = [w for w in words if w.startswith('#')]\nmentions = [w for w in words if w.startswith('@')]\n\n# Banned word check\nbanned_words = ['ugly', 'hate', 'stupid']\nflagged = [w for w in banned_words if w in caption.lower()]\n\n# Preview\npreview = caption[:50] + '...' if len(caption) > 50 else caption\n\nprint('📸 INSTAGRAM MODERATION REPORT')\nprint('═' * 45)\nprint(f'Caption    : {preview}')\nprint(f'Full length: {len(caption)} chars')\nprint(f'Word count : {len(words)} words')\nprint(f'Hashtags   : {len(hashtags)} → {hashtags}')\nprint(f'Mentions   : {len(mentions)} → {mentions}')\nprint(f'Flagged    : {\"⚠️ YES → \" + str(flagged) if flagged else \"✅ Clean\"}')\nprint(f'Upper ver  : {caption.upper()[:60]}...')",
            "solution_output": "📸 INSTAGRAM MODERATION REPORT\n═════════════════════════════════════════════\nCaption    : Just vibing at the beach 🌊 @priya_m @arjun.d...\nFull length: 103 chars\nWord count : 15 words\nHashtags   : 3 → ['#sunset', '#beachlife', '#nofilter']\nMentions   : 2 → ['@priya_m', '@arjun.dev']\nFlagged    : ⚠️ YES → ['ugly']\nUpper ver  : JUST VIBING AT THE BEACH 🌊 @PRIYA_M @ARJUN.DEV #SUNSET #B...",
            "takeaway": "At Instagram, string operations run on BILLIONS of posts daily. Every hashtag you click, every @mention that becomes a link, every comment that gets auto-flagged — it's all string processing. The concepts you just learned power real social media at scale.",
        },
    },

    # ═══════════════════════════════════════════
    # CHAPTER: CONTROL FLOW
    # ═══════════════════════════════════════════

    "if_else": {
        "title": "If / Elif / Else",
        "chapter": "control",
        "order": 4,

        "analogy": "If/Else is like a <strong>security guard at a club</strong>. The guard checks your age: IF you're 21+, you enter the VIP section. ELIF you're 18+, you go to the general area. ELSE, you get turned away. The guard checks conditions one by one and sends you to the first one that matches — then stops checking.",

        "explanation": """
<h3>Decision Making in Python</h3>
<p>Programs need to make decisions. The <code>if</code> statement lets your code choose between different paths based on conditions.</p>

<h3>Syntax</h3>
<pre class="syntax-block">
if condition:
    # runs if condition is True
elif another_condition:
    # runs if first was False, this is True
else:
    # runs if ALL above were False
</pre>

<h3>Comparison Operators</h3>
<table class="content-table">
    <tr><th>Operator</th><th>Meaning</th><th>Example</th></tr>
    <tr><td><code>==</code></td><td>Equal to</td><td><code>5 == 5</code> → True</td></tr>
    <tr><td><code>!=</code></td><td>Not equal</td><td><code>5 != 3</code> → True</td></tr>
    <tr><td><code>&gt;</code></td><td>Greater than</td><td><code>10 &gt; 5</code> → True</td></tr>
    <tr><td><code>&lt;</code></td><td>Less than</td><td><code>3 &lt; 7</code> → True</td></tr>
    <tr><td><code>&gt;=</code></td><td>Greater or equal</td><td><code>5 &gt;= 5</code> → True</td></tr>
    <tr><td><code>&lt;=</code></td><td>Less or equal</td><td><code>4 &lt;= 9</code> → True</td></tr>
</table>

<h3>Logical Operators</h3>
<p>Combine conditions with <code>and</code>, <code>or</code>, <code>not</code>:</p>
""",

        "code": '# Basic if/elif/else\nmarks = 78\n\nif marks >= 90:\n    grade = "A+"\n    print("Outstanding! 🏆")\nelif marks >= 75:\n    grade = "A"\n    print("Excellent! 🌟")\nelif marks >= 60:\n    grade = "B"\n    print("Good job! 👍")\nelif marks >= 40:\n    grade = "C"\n    print("Pass ✅")\nelse:\n    grade = "F"\n    print("Failed ❌")\n\nprint(f"Marks: {marks} → Grade: {grade}")\n\n# Combining conditions\nage = 20\nhas_id = True\n\nif age >= 18 and has_id:\n    print("Access granted")\nelse:\n    print("Access denied")',
        "output": 'Excellent! 🌟\nMarks: 78 → Grade: A\nAccess granted',

        "broken_code": '# 🔍 Find the bug!\nage = 20\n\nif age > 18\n    print("Adult")\nelse\n    print("Minor")',
        "broken_hint": "In Python, if and else statements must end with a colon (:)",
        "broken_fix": '# ✅ Fixed! Added colons\nage = 20\n\nif age > 18:          # ← colon!\n    print("Adult")\nelse:                 # ← colon!\n    print("Minor")',

        "real_product": "In Swiggy/Zomato, when you place an order, the system uses if/else logic everywhere: IF your cart is above ₹149, free delivery. ELIF you have a membership, also free. ELSE charge ₹30. IF the restaurant is closed, show 'Closed'. IF rain is heavy, increase delivery time estimate.",

        "trap": "Using <code>=</code> (assignment) instead of <code>==</code> (comparison) inside an if statement. <code>if x = 5</code> is a SYNTAX ERROR. You need <code>if x == 5</code>. One equals sign assigns, two equals signs compare. This mistake wastes hours of debugging.",

        "viva_q": "What is the difference between if-elif-else and multiple if statements?",
        "viva_a": "With if-elif-else, Python checks conditions one by one and STOPS at the first True — only ONE block executes. With multiple separate if statements, Python checks EVERY condition independently — multiple blocks can execute. Use elif when conditions are mutually exclusive (like grading), use multiple ifs when conditions can overlap.",

        "mini_build": "Movie Ticket Price Calculator",
        "mini_build_desc": "Build a ticket pricing system that charges based on age, day of week, and whether it's a 3D movie.",
        "mini_build_code": '# 🔨 Movie Ticket Price Calculator\nage = 22\nday = "Sunday"\nis_3d = True\n\n# Base price by age\nif age < 5:\n    price = 0\n    category = "Free (Infant)"\nelif age <= 12:\n    price = 100\n    category = "Child"\nelif age <= 60:\n    price = 250\n    category = "Adult"\nelse:\n    price = 150\n    category = "Senior Citizen"\n\n# Weekend surcharge\nif day in ["Saturday", "Sunday"]:\n    price += 50\n    day_type = "Weekend (+₹50)"\nelse:\n    day_type = "Weekday"\n\n# 3D surcharge\nif is_3d:\n    price += 80\n    movie_type = "3D (+₹80)"\nelse:\n    movie_type = "2D"\n\nprint("🎬 MOVIE TICKET")\nprint("─" * 30)\nprint(f"Age      : {age} ({category})")\nprint(f"Day      : {day} ({day_type})")\nprint(f"Format   : {movie_type}")\nprint(f"─" * 30)\nprint(f"TOTAL    : ₹{price}")',

        "mission": {
            "company": "Swiggy",
            "company_icon": "🍔",
            "level": "Backend Dev",
            "scenario": "You've joined Swiggy's Order Processing team. Every time a customer places an order, the backend has to calculate the final bill — applying discounts, surge pricing during rain, free delivery thresholds, and membership benefits. Your team lead says: 'Write the pricing logic. This code will run for every single order — 2 million+ orders per day.'",
            "task": "Build Swiggy's order pricing engine. Given a cart total, time of day, weather, and membership status, calculate the final amount with all conditions applied.",
            "steps": [
                "Check if cart total is above ₹149 for free delivery, else add ₹30",
                "If it's raining, add ₹20 surge charge",
                "If user has Swiggy One membership, waive delivery + give 10% off",
                "If order is between 11PM-6AM (late night), add ₹15 surcharge",
                "Apply a coupon: if cart > ₹500, give flat ₹75 off",
                "Print the complete bill breakdown",
            ],
            "skills": "if/elif/else, and/or, comparison operators, nested conditions",
            "solution": "# Swiggy Order Pricing Engine\ncart_total = 620\nis_raining = True\nhas_swiggy_one = False\norder_hour = 23  # 11 PM\n\nprint('🍔 SWIGGY ORDER BILL')\nprint('═' * 35)\nprint(f'Cart Total     : ₹{cart_total}')\n\ndelivery = 0\nsurge = 0\nlate_fee = 0\ndiscount = 0\nmember_discount = 0\n\n# Delivery fee\nif cart_total < 149:\n    delivery = 30\n    print(f'Delivery Fee   : +₹{delivery}')\nelse:\n    print(f'Delivery Fee   : FREE ✅')\n\n# Rain surge\nif is_raining:\n    surge = 20\n    print(f'Rain Surge     : +₹{surge} 🌧️')\n\n# Late night fee\nif order_hour >= 23 or order_hour < 6:\n    late_fee = 15\n    print(f'Late Night Fee : +₹{late_fee} 🌙')\n\n# Swiggy One\nif has_swiggy_one:\n    delivery = 0\n    surge = 0\n    member_discount = round(cart_total * 0.10)\n    print(f'Swiggy One     : -₹{member_discount} (10% off) 👑')\n    print(f'  + Free delivery + No surge')\n\n# Coupon\nif cart_total > 500:\n    discount = 75\n    print(f'Coupon Applied : -₹{discount} 🎟️')\n\nfinal = cart_total + delivery + surge + late_fee - discount - member_discount\nprint(f'─' * 35)\nprint(f'TOTAL TO PAY   : ₹{final}')",
            "solution_output": "🍔 SWIGGY ORDER BILL\n═══════════════════════════════════\nCart Total     : ₹620\nDelivery Fee   : FREE ✅\nRain Surge     : +₹20 🌧️\nLate Night Fee : +₹15 🌙\nCoupon Applied : -₹75 🎟️\n───────────────────────────────────\nTOTAL TO PAY   : ₹580",
            "takeaway": "At Swiggy, EVERY order goes through exactly this kind of if/elif/else logic. The pricing engine checks 15+ conditions before showing you the final price. One wrong condition = customers get charged wrong = company loses crores. This is why mastering if/else is critical.",
        },
    },

    # ═══════════════════════════════════════════
    # CHAPTER: DATA STRUCTURES
    # ═══════════════════════════════════════════

    "lists": {
        "title": "Lists",
        "chapter": "data_structures",
        "order": 5,

        "analogy": "A list is like a <strong>train with numbered coaches</strong>. Each coach (index) holds a passenger (value). You can add new coaches at the end, insert one in the middle, remove a coach, or check how many coaches the train has. Unlike a string (which is a locked train), you CAN swap passengers between coaches — lists are mutable.",

        "explanation": """
<h3>What is a List?</h3>
<p>A list is an <strong>ordered, mutable collection</strong> that can hold items of any type. Lists are one of the most used data structures in Python.</p>

<h3>Creating Lists</h3>
<p>Use square brackets <code>[]</code>:</p>

<h3>Key List Operations</h3>
<table class="content-table">
    <tr><th>Operation</th><th>Syntax</th><th>What it does</th></tr>
    <tr><td>Add to end</td><td><code>.append(x)</code></td><td>Adds x at the end</td></tr>
    <tr><td>Insert at position</td><td><code>.insert(i, x)</code></td><td>Inserts x at index i</td></tr>
    <tr><td>Remove by value</td><td><code>.remove(x)</code></td><td>Removes first occurrence of x</td></tr>
    <tr><td>Remove by index</td><td><code>.pop(i)</code></td><td>Removes and returns item at index i</td></tr>
    <tr><td>Sort</td><td><code>.sort()</code></td><td>Sorts in place</td></tr>
    <tr><td>Reverse</td><td><code>.reverse()</code></td><td>Reverses in place</td></tr>
    <tr><td>Length</td><td><code>len(list)</code></td><td>Number of items</td></tr>
</table>
""",

        "code": '# Creating lists\nfruits = ["apple", "banana", "mango", "grape"]\nnumbers = [10, 20, 30, 40, 50]\nmixed = ["hello", 42, 3.14, True]\n\n# Accessing elements\nprint(fruits[0])     # First item\nprint(fruits[-1])    # Last item\nprint(fruits[1:3])   # Slice\n\n# Modifying lists (MUTABLE!)\nfruits.append("orange")     # Add at end\nfruits.insert(1, "kiwi")    # Insert at position 1\nfruits.remove("banana")     # Remove by value\nprint(fruits)\n\n# Useful operations\nnumbers.sort(reverse=True)  # Sort descending\nprint(numbers)\nprint(f"Total items: {len(fruits)}")\nprint(f"Has mango? {\'mango\' in fruits}")',
        "output": 'apple\ngrape\n[\'banana\', \'mango\']\n[\'apple\', \'kiwi\', \'mango\', \'grape\', \'orange\']\n[50, 40, 30, 20, 10]\nTotal items: 5\nHas mango? True',

        "broken_code": '# 🔍 Find the bug!\ncolors = ["red", "green", "blue"]\nprint(colors[3])  # Get the 3rd color',
        "broken_hint": "List indexing starts at 0, not 1. So index 3 is actually the 4th element — which doesn't exist!",
        "broken_fix": '# ✅ Fixed! Index 2 is the 3rd element\ncolors = ["red", "green", "blue"]\nprint(colors[2])   # Index: 0=red, 1=green, 2=blue\n\n# Or use -1 for last element (safest)\nprint(colors[-1])  # Always gets the last one',

        "real_product": "In Spotify, your playlist is literally a list. When you add a song, it's <code>.append()</code>. When you drag a song to a new position, it's <code>.insert()</code>. When you remove a song, it's <code>.remove()</code>. Shuffle is <code>random.shuffle()</code>. The entire Spotify playlist feature is built on list operations.",

        "trap": "Confusing <code>.append()</code> with <code>.extend()</code>. If you do <code>list1.append([4,5])</code>, you get <code>[1, 2, 3, [4,5]]</code> — a nested list! But <code>list1.extend([4,5])</code> gives <code>[1, 2, 3, 4, 5]</code>. Students waste HOURS debugging this.",

        "viva_q": "What is the difference between a list and a tuple in Python?",
        "viva_a": "Both are ordered sequences, but a list is <strong>mutable</strong> (can be changed after creation — add, remove, modify elements) while a tuple is <strong>immutable</strong> (cannot be changed). Lists use square brackets <code>[]</code>, tuples use parentheses <code>()</code>. Tuples are slightly faster and use less memory, making them ideal for fixed data like coordinates <code>(x, y)</code> or database records.",

        "mini_build": "Hostel Mess Menu Manager",
        "mini_build_desc": "Build a mess menu system that stores daily meals and lets you view, add, and search items.",
        "mini_build_code": '# 🔨 Hostel Mess Menu Manager\nmenu = {\n    "Monday":    ["Poha", "Dal Rice", "Chapati Sabzi"],\n    "Tuesday":   ["Idli Sambar", "Rajma Rice", "Paratha"],\n    "Wednesday": ["Bread Butter", "Chole Rice", "Biryani"],\n}\n\n# Display full menu\nprint("🍽️  HOSTEL MESS MENU")\nprint("═" * 40)\nfor day, meals in menu.items():\n    print(f"\\n📅 {day}:")\n    for i, meal in enumerate(meals, 1):\n        print(f"   {i}. {meal}")\n\n# Add a new item to Monday\nmenu["Monday"].append("Jalebi")\nprint(f"\\n✅ Added Jalebi to Monday!")\nprint(f"Monday menu: {menu[\'Monday\']}")\n\n# Search for a dish\nsearch = "Biryani"\nprint(f"\\n🔍 Searching for {search}...")\nfor day, meals in menu.items():\n    if search in meals:\n        print(f"   Found on {day}! 🎉")',

        "mission": {
            "company": "Spotify",
            "company_icon": "🎵",
            "level": "SDE Intern",
            "scenario": "Welcome to Spotify's Music Recommendation team! Your mentor explains: 'Every user's playlist is stored as a Python list. When they add a song, remove a song, shuffle, or sort by popularity — it's all list operations under the hood. We need you to build the core playlist engine.'",
            "task": "Build Spotify's playlist engine — create a playlist, add songs, remove a song, sort by name, find a specific track, and display the queue.",
            "steps": [
                "Create a playlist list with 5 songs",
                "Add 2 new songs using .append()",
                "Insert a song at position 2 using .insert()",
                "Remove a song the user skipped using .remove()",
                "Sort the playlist alphabetically",
                "Check if a specific song exists, and print the full queue",
            ],
            "skills": "list creation, .append(), .insert(), .remove(), .sort(), len(), in",
            "solution": "# Spotify Playlist Engine\nplaylist = ['Blinding Lights', 'Levitating', 'Stay', 'Peaches', 'Montero']\nprint('🎵 SPOTIFY PLAYLIST ENGINE')\nprint('═' * 45)\nprint(f'Initial playlist ({len(playlist)} songs):')\nfor i, song in enumerate(playlist, 1):\n    print(f'  {i}. {song}')\n\n# Add new songs\nplaylist.append('As It Was')\nplaylist.append('Anti-Hero')\nprint(f'\\n➕ Added 2 songs. Total: {len(playlist)}')\n\n# Insert at position\nplaylist.insert(2, 'Flowers')\nprint(f'📌 Inserted \"Flowers\" at position 3')\n\n# User skipped a song → remove it\nplaylist.remove('Peaches')\nprint(f'⏭️ Removed \"Peaches\" (user skipped)')\n\n# Sort\nplaylist.sort()\nprint(f'\\n🔤 Sorted A→Z:')\nfor i, song in enumerate(playlist, 1):\n    print(f'  {i}. {song}')\n\n# Search\nsearch = 'Stay'\nif search in playlist:\n    pos = playlist.index(search) + 1\n    print(f'\\n🔍 \"{search}\" found at position {pos}')\nelse:\n    print(f'\\n❌ \"{search}\" not in playlist')\n\nprint(f'\\n📊 Total tracks: {len(playlist)}')",
            "solution_output": "🎵 SPOTIFY PLAYLIST ENGINE\n═════════════════════════════════════════════\nInitial playlist (5 songs):\n  1. Blinding Lights\n  2. Levitating\n  3. Stay\n  4. Peaches\n  5. Montero\n\n➕ Added 2 songs. Total: 7\n📌 Inserted \"Flowers\" at position 3\n⏭️ Removed \"Peaches\" (user skipped)\n\n🔤 Sorted A→Z:\n  1. Anti-Hero\n  2. As It Was\n  3. Blinding Lights\n  4. Flowers\n  5. Levitating\n  6. Montero\n  7. Stay\n\n🔍 \"Stay\" found at position 7\n\n📊 Total tracks: 7",
            "takeaway": "Spotify manages 100M+ playlists with 4B+ tracks. Every single playlist operation you do — add, remove, shuffle, sort — maps directly to Python list methods. The same .append() and .remove() you just learned is what powers the world's biggest music platform.",
        },
    },

    # ═══════════════════════════════════════════
    # CHAPTER: FUNCTIONS
    # ═══════════════════════════════════════════

    "functions": {
        "title": "Functions",
        "chapter": "functions",
        "order": 6,

        "analogy": "A function is like a <strong>vending machine</strong>. You put in money (arguments), press a button (call the function), and get a drink (return value). You don't need to know how the machine works inside — you just use it. And once you build one vending machine, you can use it a million times without rebuilding it.",

        "explanation": """
<h3>What is a Function?</h3>
<p>A function is a <strong>reusable block of code</strong> that performs a specific task. Instead of writing the same code again and again, you write it once inside a function and call it whenever you need it.</p>

<h3>Why Functions?</h3>
<ul>
    <li><strong>Reusability</strong> — Write once, use many times</li>
    <li><strong>Organization</strong> — Break big problems into small pieces</li>
    <li><strong>Debugging</strong> — Fix a bug in one place, fixed everywhere</li>
    <li><strong>Readability</strong> — <code>calculate_tax()</code> is clearer than 20 lines of math</li>
</ul>

<h3>Syntax</h3>
<pre class="syntax-block">
def function_name(parameter1, parameter2):
    # code block
    return result
</pre>
""",

        "code": '# Basic function\ndef greet(name):\n    return f"Hello, {name}! Welcome to VFXKart 🚀"\n\nprint(greet("Arjun"))\nprint(greet("Priya"))\n\n# Function with default parameter\ndef power(base, exp=2):\n    return base ** exp\n\nprint(power(5))      # 5^2 = 25\nprint(power(2, 10))  # 2^10 = 1024\n\n# Function with multiple returns\ndef analyze(numbers):\n    return min(numbers), max(numbers), sum(numbers)/len(numbers)\n\nmarks = [85, 92, 78, 95, 88]\nlow, high, avg = analyze(marks)\nprint(f"Low: {low}, High: {high}, Avg: {avg:.1f}")',
        "output": 'Hello, Arjun! Welcome to VFXKart 🚀\nHello, Priya! Welcome to VFXKart 🚀\n25\n1024\nLow: 78, High: 95, Avg: 87.6',

        "broken_code": '# 🔍 Find the bug!\ndef add(a, b):\n    result = a + b\n\ntotal = add(10, 20)\nprint(f"Total is: {total}")',
        "broken_hint": "The function calculates the result but never returns it. Without return, Python returns None by default.",
        "broken_fix": '# ✅ Fixed! Added return statement\ndef add(a, b):\n    result = a + b\n    return result      # ← This was missing!\n\ntotal = add(10, 20)\nprint(f"Total is: {total}")  # Total is: 30',

        "real_product": "In Paytm/GPay, when you send money, the app calls functions like <code>validate_upi(upi_id)</code>, <code>check_balance(account)</code>, <code>debit_amount(sender, amount)</code>, <code>credit_amount(receiver, amount)</code>, <code>send_notification(user, message)</code>. Each step is a separate function — if one fails, the rest don't execute. That's how your money stays safe.",

        "trap": "Forgetting the <code>return</code> statement. If your function doesn't return anything, it returns <code>None</code> by default. So <code>total = add(5, 3)</code> makes total = <code>None</code> instead of 8. Then later <code>total + 2</code> crashes with a TypeError. Always check your return!",

        "viva_q": "What is the difference between arguments and parameters? What are *args and **kwargs?",
        "viva_a": "<strong>Parameters</strong> are the variable names in the function definition: <code>def greet(name)</code> — 'name' is a parameter. <strong>Arguments</strong> are the actual values passed when calling: <code>greet('Arjun')</code> — 'Arjun' is an argument. <code>*args</code> lets a function accept any number of positional arguments as a tuple. <code>**kwargs</code> accepts any number of keyword arguments as a dictionary. Example: <code>def f(*args, **kwargs)</code> can handle <code>f(1, 2, x=3, y=4)</code>.",

        "mini_build": "CGPA Calculator",
        "mini_build_desc": "Build a function-based CGPA calculator that takes subject marks, calculates grade points, and returns the CGPA.",
        "mini_build_code": '# 🔨 CGPA Calculator\ndef get_grade_point(marks):\n    if marks >= 90: return 10\n    elif marks >= 80: return 9\n    elif marks >= 70: return 8\n    elif marks >= 60: return 7\n    elif marks >= 50: return 6\n    elif marks >= 40: return 5\n    else: return 0\n\ndef get_grade(gp):\n    grades = {10:"O", 9:"A+", 8:"A", 7:"B+", 6:"B", 5:"C", 0:"F"}\n    return grades.get(gp, "F")\n\ndef calculate_cgpa(subjects):\n    total_gp = 0\n    print("\\n📊 SEMESTER RESULT")\n    print("─" * 45)\n    print(f"{\'Subject\':<20} {\'Marks\':<8} {\'GP\':<5} {\'Grade\'}")\n    print("─" * 45)\n    \n    for name, marks in subjects.items():\n        gp = get_grade_point(marks)\n        grade = get_grade(gp)\n        total_gp += gp\n        print(f"{name:<20} {marks:<8} {gp:<5} {grade}")\n    \n    cgpa = total_gp / len(subjects)\n    print("─" * 45)\n    print(f"CGPA: {cgpa:.2f}")\n    return cgpa\n\n# Use it!\nmy_subjects = {\n    "Data Structures": 85,\n    "DBMS": 72,\n    "OS": 91,\n    "Networks": 68,\n    "Math-III": 77,\n}\n\ncalculate_cgpa(my_subjects)',

        "mission": {
            "company": "Razorpay",
            "company_icon": "💳",
            "level": "SDE-1",
            "scenario": "You've joined Razorpay's Payment Processing team. Every UPI payment, card swipe, and net banking transaction goes through a pipeline of validation functions. Your tech lead says: 'Each step of a payment is a function — validate UPI, check balance, debit sender, credit receiver, send notification. If ANY function fails, the entire transaction must stop. Build this.'",
            "task": "Build Razorpay's payment processing pipeline using functions. Each function handles one step, returns True/False, and the main flow calls them in order.",
            "steps": [
                "Create validate_upi(upi_id) — checks if valid format",
                "Create check_balance(balance, amount) — returns if sufficient",
                "Create process_payment(sender, receiver, amount) — does the transfer",
                "Create send_receipt(sender, receiver, amount) — prints confirmation",
                "Chain all functions in order — stop if any returns False",
            ],
            "skills": "def, return, parameters, default args, function chaining, bool returns",
            "solution": "# Razorpay Payment Pipeline\ndef validate_upi(upi_id):\n    if '@' not in upi_id:\n        print(f'  ❌ Invalid UPI: {upi_id}')\n        return False\n    print(f'  ✅ UPI Valid: {upi_id}')\n    return True\n\ndef check_balance(balance, amount):\n    if amount > balance:\n        print(f'  ❌ Insufficient: ₹{balance} < ₹{amount}')\n        return False\n    print(f'  ✅ Balance OK: ₹{balance} >= ₹{amount}')\n    return True\n\ndef process_payment(sender, receiver, amount):\n    print(f'  💸 ₹{amount}: {sender} → {receiver}')\n    return True\n\ndef send_receipt(sender, receiver, amount, txn_id='TXN001'):\n    print(f'  📧 Receipt sent! ID: {txn_id}')\n    print(f'     ₹{amount} from {sender} to {receiver}')\n    return txn_id\n\n# === Run Payment Pipeline ===\nprint('💳 RAZORPAY PAYMENT PIPELINE')\nprint('═' * 40)\n\nsender_upi = 'arjun@okaxis'\nreceiver_upi = 'shop@paytm'\nbalance = 5000\namount = 1299\n\nprint(f'\\nStep 1: Validate UPI')\nif not validate_upi(sender_upi):\n    print('STOPPED: Invalid UPI')\nelse:\n    print(f'\\nStep 2: Check Balance')\n    if not check_balance(balance, amount):\n        print('STOPPED: Low balance')\n    else:\n        print(f'\\nStep 3: Process Payment')\n        process_payment(sender_upi, receiver_upi, amount)\n        print(f'\\nStep 4: Send Receipt')\n        txn = send_receipt(sender_upi, receiver_upi, amount)\n        print(f'\\n🎉 Payment Complete! Ref: {txn}')",
            "solution_output": "💳 RAZORPAY PAYMENT PIPELINE\n════════════════════════════════════════\n\nStep 1: Validate UPI\n  ✅ UPI Valid: arjun@okaxis\n\nStep 2: Check Balance\n  ✅ Balance OK: ₹5000 >= ₹1299\n\nStep 3: Process Payment\n  💸 ₹1299: arjun@okaxis → shop@paytm\n\nStep 4: Send Receipt\n  📧 Receipt sent! ID: TXN001\n     ₹1299 from arjun@okaxis to shop@paytm\n\n🎉 Payment Complete! Ref: TXN001",
            "takeaway": "At Razorpay, the real payment pipeline has 20+ functions chained exactly like this. validate() → authenticate() → authorize() → debit() → credit() → notify(). If ANY function returns False, the whole pipeline stops — that's how your money stays safe. Functions aren't just theory — they're the backbone of every fintech app.",
        },
    },
}


# ═══════════════════════════════════════════
# HELPER: Get ordered topic list for sidebar
# ═══════════════════════════════════════════
def get_python_topics_ordered():
    """Return topics sorted by order for sidebar navigation."""
    return sorted(PYTHON_TOPICS.items(), key=lambda x: x[1]["order"])


def get_python_nav(current_topic_id):
    """Get previous/next topic for navigation."""
    ordered = get_python_topics_ordered()
    ids = [t[0] for t in ordered]

    if current_topic_id not in ids:
        return None, None

    idx = ids.index(current_topic_id)
    prev_id = ids[idx - 1] if idx > 0 else None
    next_id = ids[idx + 1] if idx < len(ids) - 1 else None

    prev_topic = PYTHON_TOPICS[prev_id] if prev_id else None
    next_topic = PYTHON_TOPICS[next_id] if next_id else None

    return (
        {"id": prev_id, **prev_topic} if prev_topic else None,
        {"id": next_id, **next_topic} if next_topic else None,
    )


def get_topics_by_chapter():
    """Group topics by chapter for the landing page."""
    chapters = {}
    for topic_id, topic in sorted(PYTHON_TOPICS.items(), key=lambda x: x[1]["order"]):
        ch = topic["chapter"]
        if ch not in chapters:
            chapters[ch] = []
        chapters[ch].append({"id": topic_id, **topic})
    return chapters
