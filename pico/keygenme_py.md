`keygenme.py` is a [picoCTF](https://play.picoctf.org) challenge in the reverse engineering category. You have to retrieve the key in order to access the full version of the `"Arcane Calculator"`.
Let's run the python script using our command line.

```
$ python3 keygenme-trial.py
```

We can see a prompt as well as a list of options.

```
===============================================
Welcome to the Arcane Calculator, FRASER!

This is the trial version of Arcane Calculator.
The full version may be purchased in person near
the galactic center of the Milky Way galaxy. 
Available while supplies last!
=====================================================


___Arcane Calculator___

Menu:
(a) Estimate Astral Projection Mana Burn
(b) [LOCKED] Estimate Astral Slingshot Approach Vector
(c) Enter License Key
(d) Exit Arcane Calculator
What would you like to do, FRASER (a/b/c/d)?
```

Before taking a look inside we can note **2**  interesting stuff. These are the option `c` that lets us enter the license key and that for some reason the program is calling us `"FRASER"`.

## Peeking inside
Looking at the first lines  already we can see how the key is structured. From a first glance, a brute force attack comes to mind. Later on we will see why that attack is not appropriate for this situation.  We also see that `"FRASER"` is in fact a username and is set as a constant. Lets keep that in mind.

```py
username_trial = "FRASER"
bUsername_trial = b"FRASER"

key_part_static1_trial = "picoCTF{1n_7h3_|<3y_of_"
key_part_dynamic1_trial = "xxxxxxxx"
key_part_static2_trial = "}"
key_full_template_trial = key_part_static1_trial + key_part_dynamic1_trial + key_part_static2_trial
```

Alright. There are a lot of functions in the application so lets start our investigation by declaring what functions are important for the generation of the dynamic part of the license key and focus on them.
- `menu_trial()` doesn't look important. It validates the choice entered by the user and afterwards runs different functions depending on the users input.
- We can easily ignore the `validate_choice` function as well as the `estimate_burn()` one.
- The `locked_estimate_vector()` just prints a warning that informs the user that a feature he tried to use is accessible only through the full version of the product.
Now we are getting somewhere.
- The `enter_license()` function has some interesting calls. Firstly it asks the user to enter the license key. Then it runs the `check_key` function using as arguments the license key entered as well as the byte version of the username constant that is stored as `bUsername_trial` 
If the `check_key` call returns true then the application proceeds to decrypt the full version using the license key.

## Dynamic Key
The `check_key` function firstly checks if the key is even long enough. After that the application checks the first part of our license key comparing it to the 1st static part using a for loop (that check will be quite eazy to bypass copy paste is still a thing!).  

```py
def check_key(key, username_trial):

    global key_full_template_trial

    if len(key) != len(key_full_template_trial):
        return False
    else:
        # Check static base key part --v
        i = 0
        for c in key_part_static1_trial:
            if key[i] != c:
                return False

            i += 1
```

The iterator is now where the dynamic part begins. Next we see a big tree of `if/else` statements that check the validity of the dynamic part of the key.

```py
if key[i] != hashlib.sha256(username_trial).hexdigest()[4]:
    return False
else:
    i += 1

if key[i] != hashlib.sha256(username_trial).hexdigest()[5]:
    return False
else:
    i += 1

if key[i] != hashlib.sha256(username_trial).hexdigest()[3]:
    return False
else:
    i += 1

if key[i] != hashlib.sha256(username_trial).hexdigest()[6]:
    return False
else:
    i += 1

if key[i] != hashlib.sha256(username_trial).hexdigest()[2]:
    return False
else:
    i += 1

if key[i] != hashlib.sha256(username_trial).hexdigest()[7]:
    return False
else:
    i += 1

if key[i] != hashlib.sha256(username_trial).hexdigest()[1]:
    return False
else:
    i += 1

if key[i] != hashlib.sha256(username_trial).hexdigest()[8]:
    return False
```

Notice that each letter of the dynamic part gets compared to a substitute of the [SHA256](https://wikipedia.org/wiki/SHA-2) hash of the username. This is really easy to exploit.

## Exploitation
Firstly lets import `hashlib` so that we can craft the required SHA256 hash.

```py
import hashlib
```

From the application's source code we will . . . borrow a bunch of variables. These are the license key's structure as well as the byte encoded username.

```py
import hashlib

bUsername_trial = b"FRASER"

key_part_static1_trial = "picoCTF{1n_7h3_|<3y_of_"
key_part_dynamic1_trial = "xxxxxxxx"
key_part_static2_trial = "}"
key_full_template_trial = key_part_static1_trial + key_part_dynamic1_trial + key_part_static2_trial
```

Now we will store the specific indexes used from the application in a list.

```py
indexes = [4, 5, 3, 6, 2, 7, 1, 8]
```

Finally we craft the dynamic part one letter at a time and append it to the result

```py
dynamic_key = ""

for i in indexes:
        dynamic_key += hashlib.sha256(username_trial).hexdigest()[i]
```

After we craft the dynamic part, we only need to put the pieces together.

```py
license_key = key_part_static1_trial + dynamic_key + key_part_static2_trial

print(f"[+] License Key: {license_key}")
```

And thats it! Lets now run the exploit and get our sweet license key.

```
$ python exploit.py
[+] License Key: picoCTF{1n_7h3_|<3y_of_ac73dc29}
```

I hope you had a great time learning and exploiting this application! This is my first writeup, more to come.

- skelet0n 
