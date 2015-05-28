class PymemError(Exception):
     def __init__(self, message):
        super(PymemError, self).__init__(message)


class ProcessError(PymemError):
    def __init__(self, message):
        super(ProcessError, self).__init__(self, message)


class ProcessNotFound(ProcessError):
    def __init__(self, process_name):
        message = 'Could not find process: {}'.format(process_name)
        super(ProcessNotFound, self).__init__(message)


class CouldNotOpenProcess(ProcessError):
    def __init__(self, process_id):
        message = 'Could not open process: {}'.format(process_id)
        super(CouldNotOpenProcess, self).__init__(message)