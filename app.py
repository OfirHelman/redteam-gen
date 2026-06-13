import csv
import io
import streamlit as st
from generate import generate_dataset

st.title("Attack Dataset Generator")

scenario = st.text_input("Scenario", value="ransomware")

def to_csv(rows):
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=["process_name", "command_line", "label"])
    writer.writeheader()
    writer.writerows(rows)
    return buf.getvalue()

if st.button("Generate"):
    with st.spinner("Generating... this takes a bit"):
        rows, story = generate_dataset(scenario, 20, 200)

    mal = [r for r in rows if r["label"] == "malicious"]

    st.success(f"Generated {len(rows)} rows: {len(mal)} malicious, {len(rows) - len(mal)} benign")

    st.subheader("Attack story")
    st.write(story)

    st.download_button(
        "Download dataset.csv",
        data=to_csv(rows),
        file_name="dataset.csv",
        mime="text/csv",
    )
    st.download_button(
        "Download ground_truth.csv",
        data=to_csv(mal),
        file_name="ground_truth.csv",
        mime="text/csv",
    )

    st.subheader("Preview")
    st.dataframe(rows)