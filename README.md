# Yara

```
brew install yara
yara Example_rule.yar target.txt

# recursive scan file in dictionary
yara -r rule/30c438fd29c43a0faf9760b600695961f520d585.yar .

# multiple rules
yara ./rules/* -r .
```

