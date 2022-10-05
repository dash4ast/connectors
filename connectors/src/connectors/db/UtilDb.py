from connectors.persistence.Analysis import Analysis


def create_analysis(application_name, analysis_type, now):
    analysis = Analysis()
    analysis.analysis_date = now
    analysis.application = application_name
    analysis.analysis_type = analysis_type
    return analysis


def add_vulnerability(db_session, vulnerability):
    db_session.add(vulnerability)
    db_session.commit()
    db_session.flush()


def add_analysis(db_session, analysis):
    db_session.add(analysis)
    db_session.commit()
    db_session.flush()


def update_vulnerability(db_session, status, vulnerability):
    setattr(vulnerability, 'status', status)
    db_session.commit()
    db_session.flush()
