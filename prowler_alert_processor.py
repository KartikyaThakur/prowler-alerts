import re
import datetime

class ProwlerAlertProcessor:
    
    def __init__(self):
        self.__categories = []

    __production_backup_partition = '*** BACKUP FILES ***'
    __epoch = '1/1/1968'

    def __extract_alert_lines(self, alert_contents):
        alert_lines = AlertPattern.line.findall(alert_contents)
        alert_line_indexes = []
        alerts = []
        for alert_line in alert_lines:
            if alert_line.endswith('\r\n\r'):
                alert_line = alert_line[:len(alert_line) - 3]
            elif alert_line.endswith('\r\n'):
                alert_line = alert_line[:len(alert_line) - 2]
            position = alert_contents.find(alert_line)
            for alert_line_index in alert_line_indexes:
                if alert_line_index['alert_content'] == alert_line:
                    position = alert_contents.find(alert_line, position + 1)
            alert_line_indexes.append({'alert_content': alert_line, 'position': position})
            alerts.append({'alert_content': alert_line, 'position': position})
        return alerts
    
    def __extract_alert_programs(self, alert_contents, is_production):
        program_names = AlertPattern.program.findall(alert_contents)
        programs = []
        for program_name in program_names:
            extra_information = AlertPattern.program_extra_information.findall(program_name)[0]
            universe_date = AlertPattern.date.findall(program_name)[0]
            raw_program = {'program_name': program_name.replace('_{0}'.format(extra_information),'').replace('_{}'.format(universe_date),''), 'position': alert_contents.index(program_name), 'is_production': is_production, 'alerts': []}
            if universe_date:
                raw_program['date'] = (datetime.datetime.strptime(self.__epoch, '%m/%d/%Y') + datetime.timedelta(days=int(universe_date))).strftime('%m/%d/%Y')
            if extra_information:
                raw_program['extra_information'] = extra_information
            programs.append(raw_program)

        return programs
    
    def __is_prowler_alert_mail(self, mailbody):
        return AlertPattern.subject.search(mailbody) != None

    def __process_alert_content(self, alert_contents, is_production):
        programs = self.__extract_alert_programs(alert_contents, is_production)
        programs.reverse()
        alerts = self.__extract_alert_lines(alert_contents)
        for alert in alerts:
            for program in programs:
                if alert['position'] > program['position']:
                    program['alerts'].append(alert)
                    break
        programs.reverse()

        return {'programs': programs}
    
    def process_mail(self, mailbody):
        if self.__is_prowler_alert_mail(mailbody):
            alert_contents = mailbody.split(self.__production_backup_partition)
            production_alerts = self.__process_alert_content(alert_contents[0], True)
            backup_alerts = self.__process_alert_content(alert_contents[1], False)
            return production_alerts + backup_alerts
        else:
            return None

class AlertPattern:
    subject = re.compile(r'\d+ & \d+ errors found by prowler', re.MULTILINE|re.DOTALL)
    program = re.compile(r'(?<=\r\n)(?:[a-zA-Z0-9_.])+?(?=\r\n  LINE)', re.MULTILINE|re.DOTALL)
    program_extra_information = re.compile(r'(?<=_)\d+(?=_)')
    date = re.compile(r'(?<=_)\d+(?!_|\d)')
    line = re.compile(r'LINE\s+\d+(?:.(?!LINE|\*\*\*|(?<=\r\n)(?:[a-zA-Z0-9_.])+?(?=\r\n  LINE)))*', re.MULTILINE|re.DOTALL)


class ProwlerAlert:

    def __init__(self, is_production, category, program, description):
        self.is_production = is_production
        self.category = category
        self.program = program
        self.description = description

class Cateogry:

    def __init__(self, is_critical, regex_string, name):
        self.is_critical = is_critical
        self.pattern = re.compile(regex_string)
        self.name = name
