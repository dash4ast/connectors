def verify_size(json_data):
    # Convert the JSON string to bytes using UTF-8 encoding
    bytes_data = json_data.encode('utf-8')

    # Get the size of the JSON data in bytes
    json_size = len(bytes_data)

    print(f"JSON size: {json_size} bytes")

    if (json_size > 5000):
      return False
    return True