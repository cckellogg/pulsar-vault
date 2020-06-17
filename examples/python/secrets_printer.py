
def _read_file(filename):
  with open(filename, 'r') as reader:
    return reader.read().strip()


def process(input):
  username = _read_file('/vault/secrets/username')
  password = _read_file('/vault/secrets/password')
  print('secrets username=%s password=%s' % (username, password))
