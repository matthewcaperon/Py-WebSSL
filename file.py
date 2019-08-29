
class File:

    @staticmethod
    def write(path, data):

        print("Saving: " + path)

        with open(path, 'w') as f:
            f.write(data)

    def write_bytes(path, data):
        print("Saving: " + path)

        with open(path, 'wb') as f:
            f.write(data)

    @staticmethod
    def read(path):

        with open(path, 'r') as f:
            data = f.read()

        return data
