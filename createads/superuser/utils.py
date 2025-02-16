# utils.py (This should be available in each app or as a shared utility)
import random
import string

def generate_unique_id(model, field, length=5):
    """Generates a unique alphanumeric ID of the specified length."""
    characters = string.ascii_letters + string.digits
    while True:
        unique_id = ''.join(random.choices(characters, k=length))
        if not model.objects.filter(**{field: unique_id}).exists():
            return unique_id
