from flask import Blueprint, render_template, abort, redirect, url_for

from content.python_content import (
    PYTHON_TOPICS, PYTHON_CHAPTERS,
    get_python_topics_ordered, get_python_nav, get_topics_by_chapter,
)

learning_bp = Blueprint("learning", __name__, url_prefix="/learning")


# ==============================
# 📌 HOME
# ==============================
@learning_bp.route("/")
def learning_ug():
    return render_template("learning_ug.html")


@learning_bp.route("/course/btech")
def btech_list():
    return render_template("btech_list.html")


# ==============================
# 📌 COURSES DATA (original)
# ==============================
COURSES = {
    "btech_cs": {
        "name": "B.Tech Computer Science Engineering",
        "subjects": {
            "programming": ["C Programming", "Data Structures", "Algorithms", "OOP"],
            "systems": ["Operating Systems", "Computer Networks", "Databases"],
            "advanced": ["AI/ML", "Cloud Computing", "Cybersecurity"],
        },
    },
    "btech_it": {
        "name": "B.Tech Information Technology",
        "subjects": {
            "fundamentals": ["Programming Fundamentals", "Data Structures"],
            "it_core": ["Web Technologies", "Networking", "Software Engineering"],
            "enterprise": ["Cloud & DevOps", "Big Data", "Cybersecurity"],
        },
    },
    "btech_ece": {
        "name": "B.Tech Electronics & Communication Engineering",
        "subjects": {
            "electronics": ["Digital Electronics", "Analog Circuits", "Signals & Systems"],
            "comm": ["Digital Communication", "VLSI Design", "Embedded Systems"],
            "advanced": ["RF & Microwave", "IoT"],
        },
    },
    "btech_eee": {
        "name": "B.Tech Electrical & Electronics Engineering",
        "subjects": {
            "electrical": ["Electrical Machines", "Power Systems", "Control Systems"],
            "electronics": ["Power Electronics", "Renewable Energy"],
        },
    },
    "btech_me": {
        "name": "B.Tech Mechanical Engineering",
        "subjects": {
            "core": ["Thermodynamics", "Fluid Mechanics", "Strength of Materials"],
            "design": ["Machine Design", "CAD/CAM", "Manufacturing"],
            "advanced": ["Robotics", "Automobile Engineering"],
        },
    },
    "btech_ce": {
        "name": "B.Tech Civil Engineering",
        "subjects": {
            "structures": ["Structural Analysis", "RCC Design", "Steel Structures"],
            "geotech": ["Soil Mechanics", "Foundation Engineering"],
        },
    },
    "btech_chem": {
        "name": "B.Tech Chemical Engineering",
        "subjects": {
            "fundamentals": ["Chemical Process Calculations", "Thermodynamics"],
            "processes": ["Heat Transfer", "Mass Transfer"],
        },
    },
    "btech_aero": {
        "name": "B.Tech Aeronautical Engineering",
        "subjects": {
            "aerodynamics": ["Aerodynamics 1", "Flight Mechanics", "Propulsion"],
            "structures": ["Aircraft Structures", "Avionics"],
        },
    },
    "btech_bme": {
        "name": "B.Tech Biomedical Engineering",
        "subjects": {
            "biology": ["Human Anatomy", "Biomechanics"],
            "technology": ["Medical Imaging", "Tissue Engineering", "Biomedical Signal Processing"],
        },
    },
    "btech_env": {
        "name": "B.Tech Environmental Engineering",
        "subjects": {
            "environment": ["Environmental Chemistry", "Hydrology", "Waste Management"],
            "pollution": ["Air Pollution Control", "Water Treatment"],
        },
    },
    "btech_mechat": {
        "name": "B.Tech Mechatronics",
        "subjects": {
            "systems": ["Control Systems", "Sensors and Actuators"],
            "robotics": ["Industrial Robotics", "Embedded Systems"],
        },
    },
    "btech_phy": {
        "name": "B.Tech Engineering Physics",
        "subjects": {
            "physics": ["Quantum Mechanics", "Electromagnetics", "Solid State Physics"],
            "advanced": ["Nanotechnology", "Optics", "Nuclear Physics"],
        },
    },
    "bca": {
        "name": "BCA",
        "subjects": {
            "python": ["Basics", "Functions", "OOP", "Modules"],
            "web": ["HTML", "CSS", "JavaScript"],
            "cf": ["Computer Basics", "OS", "Networking"],
        },
    },
}


# ==============================
# 📌 COURSE PAGE (original)
# ==============================
@learning_bp.route("/course/<course_id>")
def course(course_id):
    if course_id == "btech":
        return render_template("btech_list.html")

    course = COURSES.get(course_id)
    if not course:
        abort(404)

    return render_template(
        "subjects.html",
        course_name=course["name"],
        subjects=course["subjects"],
        course_id=course_id,
    )


# ==============================
# 📌 SUBJECT PAGE (original)
# ==============================
@learning_bp.route("/subject/<course_id>/<subject_name>")
def subject(course_id, subject_name):
    course = COURSES.get(course_id)
    if not course:
        abort(404)

    topics = course["subjects"].get(subject_name)
    if not topics:
        abort(404)

    return render_template(
        "topics.html",
        subject_name=subject_name,
        course_id=course_id,
        topics=topics,
    )


# ==============================
# 📌 TOPIC PAGE (original)
# ==============================
@learning_bp.route("/topic/<course_id>/<subject_name>/<topic_name>")
def topic(course_id, subject_name, topic_name):
    course = COURSES.get(course_id)
    if not course:
        abort(404)

    topics = course["subjects"].get(subject_name)
    if not topics:
        abort(404)

    original_topic = None
    for t in topics:
        if t.replace(" ", "_").lower() == topic_name:
            original_topic = t
            break

    if not original_topic:
        abort(404)

    content = f"""
    <h2>{original_topic}</h2>
    <p>This is explanation of <b>{original_topic}</b></p>
    <h3>Example:</h3>
    <pre>
print("Hello VFXKart 🚀")
    </pre>
    """

    return render_template(
        "topic.html",
        title=original_topic,
        content=content,
        course_id=course_id,
        subject_name=subject_name,
    )


# ==============================
# 📌 COURSE EXPLORER (original)
# ==============================
@learning_bp.route("/explore/<course_id>")
def explore_default(course_id):
    course = COURSES.get(course_id)
    if not course:
        abort(404)

    subjects = list(course["subjects"].keys())
    if not subjects:
        abort(404)

    first_subject = subjects[0]
    first_topic = course["subjects"][first_subject][0]
    formatted_topic = first_topic.replace(" ", "_").lower()
    return redirect(
        url_for(
            "learning.explore_topic",
            course_id=course_id,
            subject_name=first_subject,
            topic_name=formatted_topic,
        )
    )


@learning_bp.route("/explore/<course_id>/<subject_name>/<topic_name>")
def explore_topic(course_id, subject_name, topic_name):
    course = COURSES.get(course_id)
    if not course:
        abort(404)

    topics_for_subject = course["subjects"].get(subject_name)
    if not topics_for_subject:
        abort(404)

    original_topic = None
    for t in topics_for_subject:
        if t.replace(" ", "_").lower() == topic_name:
            original_topic = t
            break

    if not original_topic:
        abort(404)

    content = f"""
    <p>This is the detailed explanation of <b>{original_topic}</b> in the <strong>{course['name']}</strong> course.</p>
    <h3>Example:</h3>
    <pre>
def learn_{original_topic.replace(' ', '_').lower()}():
    print("Welcome to {original_topic} in {course['name']} 🚀")
    return True
    </pre>
    """

    flat_topics = []
    for subj, subj_topics in course["subjects"].items():
        for t in subj_topics:
            flat_topics.append(
                {"subject": subj, "topic": t, "formatted": t.replace(" ", "_").lower()}
            )

    current_idx = next(
        (
            i
            for i, item in enumerate(flat_topics)
            if item["subject"] == subject_name and item["formatted"] == topic_name
        ),
        -1,
    )

    prev_topic = flat_topics[current_idx - 1] if current_idx > 0 else None
    next_topic = (
        flat_topics[current_idx + 1] if current_idx < len(flat_topics) - 1 else None
    )

    return render_template(
        "course_explorer.html",
        course=course,
        course_id=course_id,
        current_subject=subject_name,
        current_topic_formatted=topic_name,
        original_topic=original_topic,
        content=content,
        prev_topic=prev_topic,
        next_topic=next_topic,
    )


# ══════════════════════════════════════════════════
# 📌 HINGLISH TUTOR (STARTUP IDEA #3)
# ══════════════════════════════════════════════════
@learning_bp.route("/hinglish")
def hinglish_tutor():
    """Hinglish AI Tutor — Vernacular bridge for engineering students."""
    return render_template("hinglish_tutor.html")


# ══════════════════════════════════════════════════
# 📌 NEW: PYTHON LEARNING SYSTEM (VFXKart Unique)
# ══════════════════════════════════════════════════


@learning_bp.route("/python")
def python_landing():
    """Landing page for Learn Python — shows all chapters and topics."""
    chapters_data = get_topics_by_chapter()
    return render_template(
        "learn_language.html",
        language="Python",
        language_icon="🐍",
        language_desc="The world's most popular programming language. Used in AI, Web Development, Data Science, Automation, and more.",
        chapters=PYTHON_CHAPTERS,
        topics_by_chapter=chapters_data,
    )


@learning_bp.route("/python/<topic_id>")
def python_topic(topic_id):
    """Individual Python topic page with all 6 unique content layers."""
    topic_data = PYTHON_TOPICS.get(topic_id)
    if not topic_data:
        abort(404)

    prev_topic, next_topic = get_python_nav(topic_id)
    ordered_topics = get_python_topics_ordered()

    # Build sidebar data grouped by chapter
    chapters_data = get_topics_by_chapter()

    return render_template(
        "learn_topic.html",
        language="Python",
        topic_id=topic_id,
        topic=topic_data,
        chapters=PYTHON_CHAPTERS,
        topics_by_chapter=chapters_data,
        prev_topic=prev_topic,
        next_topic=next_topic,
    )