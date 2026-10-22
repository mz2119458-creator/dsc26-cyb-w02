# AI usage: dsc26-cyb-w02

Keep the three headings below exactly as they are. The grader stops and scores 0 if this file is
missing or any of the three headings is missing. It does not score what you write; your Track
Mentor reads it, and the W8 defence can ask about it.

## Tools

I used ChatGPT to help generate the initial structure for the `tmcheck` code and to generate ideas for the eleven new threats in the YAML model.

## What AI got wrong

The AI initially wrote `isinstance(value, int)` to check if the score was valid. However, in Python, `True` passes this check because booleans are subclasses of integers. I noticed this when I wrote a local test that passed `likelihood: true` and it did not raise a `BAD_SCORE` issue. I fixed it by changing it to `isinstance(value, int) and not isinstance(value, bool)`. 

## In my own words

1. Why does a data store have no Spoofing threats in STRIDE per element, and where does that threat go instead?
A data store is just a passive place where data sits. It does not have an identity and does not initiate actions, so it cannot be impersonated. Spoofing threats are assigned to the processes or external entities that interact with the data store, because they are the ones presenting an identity to access it.

2. Which of your eleven new threats would you fix first, and why that one?
I would fix the unencrypted crossing threat on the flow from the analyst console to the case database first. This is because it involves sensitive customer PII moving in plaintext over the network, which is a direct confidentiality risk. It is also a quick fix by just enabling TLS on that connection.
