

class ErrorOr:
    def __init__(self, value=None, error=None):
        self._error = error
        if error == None:
            self._value = value

    @property
    def Value(self):
        if self.IsError:
            raise self._error
        return self._value

    @property
    def IsError(self):
        return self._error != None

    @property
    def Error(self):
        return self._error

    def map(self, fn):
        if self.IsError:
            return ErrorOr(error=self._error)
        return ErrorOr(value=fn(self._value))

def catch(fn, *args, **kwargs):
    try:
        return ErrorOr(value=fn(*args, **kwargs))
    except Exception as e:
        return ErrorOr(error=e)

