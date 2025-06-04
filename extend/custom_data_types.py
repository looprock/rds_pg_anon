from faker import Faker

fake = Faker()

# CustomDataTypes is a class that contains methods for generating fake data.
# technically you only need to define a method, but you can also pass in arguments to the method.
# Example:
# {
#     "anonymize": {
#         "custom": {
#             "method": "phone_number_list",
#             "args": [3]
#         }
#     }
# }

class CustomDataTypes:
    def __init__(self):
        pass

    def example(self):
        return "example_value"

    def phone_number_list(self, args: list) -> list:
        # set a default count of 2, but accept a count as an argument
        count = 2
        if args:
            count = args[0]
        return_list = []
        for i in range(count):
            return_list.append(fake.phone_number())
        return return_list

    def phone_dict_list(self, args: list) -> list:
        # [{'phoneType': 'office', 'phoneNumber': '555-555-1212'}]
        return_list = []
        # default phone types but accept a list of phone types to generate numbers for
        phone_types = ["office"]
        if args:
            phone_types = args
        for phone_type in phone_types:
            return_dict = {}
            return_dict["phoneType"] = phone_type
            return_dict["phoneNumber"] = fake.phone_number()
            return_list.append(return_dict)
        return return_list

    def firstname_data_dict(self) -> dict:
        return {"data": fake.first_name()}

    def lastname_data_dict(self) -> dict:
        return {"data": fake.last_name()}

    def email_data_dict(self) -> dict:
        return {"data": fake.email()}

    def phone_data_dict(self) -> dict:
        return {"data": fake.phone_number()}

    def currentLocation_data_dict(self) -> dict:
        return {"data": fake.city()}

def fake_data_dict(self) -> dict:
    data = {}
    data["firstName"] = {"data": fake.first_name()}
    data["lastName"] = {"data": fake.last_name()}
    data["email"] = {"data": fake.email()}
    data["currentLocation"] = {"data": fake.city()}
    data["phoneNumber"] = {"data": fake.phone_number()}
    return data

def fake_data_string(self) -> str:
    return str(self.fake_data_dict())
