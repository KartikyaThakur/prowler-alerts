from prowler_alert_processor import ProwlerAlertProcessor
import os
import json

def main():
    __dir_email = 'emails/'
    __dir_processed = 'processed/'
    file_names = os.listdir(__dir_email)
    if not os.path.exists(__dir_processed):
        os.makedirs(__dir_processed)
    alert_processor = ProwlerAlertProcessor()
    processed_alerts = []
    for file_name in file_names:
        with open(__dir_email + file_name, 'r') as email_file:
            data = email_file.read()
            processed_alert = alert_processor.process_mail(data)
            processed_alerts.append(processed_alert)

    with open(__dir_processed + 'processed.json', 'w') as processed_file:
        processed_file.write(json.dumps(processed_alerts))

main()