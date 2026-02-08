import streamlit as st
import time
import requests

st.title("Fraud Guard")

user_input = st.text_area("Paste suspicious text / URL")

#

#


if st.button("Analyze"):
    if user_input.strip() == "":
        st.error("Please paste some text or URL")
    else:
        with st.spinner("Analyzing..."):

            response = requests.post(
                "http://127.0.0.1:8000/analyze",
                json={"text": user_input}
            ).json()


            result = response["result"]
            st.markdown(
            f"""
            <div style="background-color:{result['verdict_color']};
                        padding:15px;
                        border-radius:10px;
                        color:white;">
                <h3>{result['verdict']}</h3>
                <p>Risk Score: {result['risk_score']}</p>
                <p>Confidence: {result['confidence']}</p>
            </div>
            """,
            unsafe_allow_html=True
            )

            st.subheader("Why is this risky?")
            for reason in response["explanation"]:
                st.write("•", reason)
                
            st.subheader("Psychological Triggers")
            for trigger in response["analysis"]["psychological_triggers"]:
                st.write(f"**{trigger['type']}** – {trigger['description']}")

            st.subheader("Technical Flags")
            for flag in response["analysis"]["technical_flags"]:
                st.write(
                f"**{flag['type']}** ({flag['severity']}) – {flag['description']}"
            )

            




            

        ##


