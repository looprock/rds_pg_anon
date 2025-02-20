# defaults

You can customize the set of defaults to use when intitializing the database state by modifying the defaults.json file here.

# data types

You can create custom data types by adding methods to custom_data_types.py.


You can pass arguments into your custom types by suffixing the method with ':' and providing a comma separated list after, RE: custom.phone_number_list:3. This would execute the CustomDataTypes.phone_number_list(3) (though that will come in as a string value, so be sure to convert to an int.)



# patch (coming soon!)

You can run custom sql by adding it to the patch directory