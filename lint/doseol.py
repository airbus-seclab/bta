from pylint.interfaces import IRawChecker
from pylint.checkers import BaseChecker

class DOSEOLChecker(BaseChecker):
    """Check absense of DOS end of lines (CR)"""

    __implements__ = IRawChecker

    name = 'dos-eol'
    msgs = {'W9902': ('Used CRLF instead of LF', 'dos-eol',
                      'Used when lines end with CRLF instead of LF'),
            }
    options = ()

    def process_module(self, node):
        """process a module

        the module's content is accessible via node.file_stream object
        """
        for (lineno, line) in enumerate(node.file_stream):
            if line.endswith('\r\n'):
                self.add_message('W9902', line=lineno)


def register(linter):
    """required method to auto register this checker"""
    linter.register_checker(DOSEOLChecker(linter))

