import streamlit as st
import requests

# ---------------- PAGE CONFIG ----------------
st.set_page_config(page_title="Fraud Guard", layout="centered")

# ---------------- BACKGROUND IMAGE ----------------
st.markdown(
    """
    <style>
    .stApp {
        background-image: url("https://images.unsplash.com/photo-1580894894513-541e068a3e2b");
        background-size: cover;
        background-attachment: fixed;
    }
    .glass {
        background: rgba(255, 255, 255, 0.88);
        padding: 25px;
        border-radius: 16px;
        box-shadow: 0 8px 30px rgba(0,0,0,0.15);
    }
    .verdict-box {
        padding: 20px;
        border-radius: 14px;
        color: white;
        text-align: center;
        margin-top: 20px;
    }
    .metric {
        background: rgba(255,255,255,0.25);
        padding: 10px;
        border-radius: 10px;
        margin: 5px;
        font-weight: bold;
    }
    </style>
    """,
    unsafe_allow_html=True
)

# ---------------- MAIN CARD ----------------
st.markdown("<div class='glass'>", unsafe_allow_html=True)

st.markdown("<h1 style='text-align:center;'>Welcome to Fraud Guard</h1>", unsafe_allow_html=True)
st.markdown(
    "<p style='text-align:center; font-size:16px; color:#555;'>"
    "“Modern problems require modern solutions.”</p>",
    unsafe_allow_html=True
)

st.markdown("<br>", unsafe_allow_html=True)

st.markdown("**Paste suspicious mail / URL here**")
user_input = st.text_area("", height=150)

# ---------------- ANALYSE BUTTON ----------------
analyze = st.button("🔍 ANALYSE")

st.markdown("</div>", unsafe_allow_html=True)

# ---------------- RESULT SECTION ----------------
if analyze:
    if user_input.strip() == "":
        st.error("Please paste some text or URL")
    else:
        with st.spinner("Analyzing..."):
            response = requests.post(
                "http://127.0.0.1:8000/analyze",
                json={"text": user_input}
            ).json()

            result = response["result"]

            # Verdict Box
            st.markdown(
                f"""
                <div class='verdict-box' style='background-color:{result['verdict_color']}'>
                    <h2>{result['verdict'].replace('_', ' ')}</h2>
                    <div style="display:flex; justify-content:space-around;">
                        <div class='metric'>Risk Score<br>{result['risk_score']}</div>
                        <div class='metric'>Confidence<br>{int(result['confidence']*100)}%</div>
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )

            st.markdown("<br>", unsafe_allow_html=True)

            # ---------------- ACTION BUTTONS ----------------
            col1, col2, col3 = st.columns(3)

            with col1:
                show_why = st.button("Why is this Risky?")
            with col2:
                show_psy = st.button("Psychological Triggers")
            with col3:
                show_tech = st.button("Technical Flags")

            # ---------------- MESSAGE BOX ----------------
            if show_why:
                st.info("\n".join(response["explanation"]))

            if show_psy:
                if response["analysis"]["psychological_triggers"]:
                    for t in response["analysis"]["psychological_triggers"]:
                        st.warning(f"**{t['type']}** — {t['description']}")
                else:
                    st.success("No psychological manipulation detected.")

            if show_tech:
                if response["analysis"]["technical_flags"]:
                    for f in response["analysis"]["technical_flags"]:
                        st.error(f"**{f['type']} ({f['severity']})** — {f['description']}")
                else:
                    st.success("No technical threats detected.")
