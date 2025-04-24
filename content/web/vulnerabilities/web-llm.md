---
title: "Web LLM"
weight: 27
description: "Explore how to identify and exploit vulnerabilities in web-integrated LLM APIs. Learn techniques like API mapping, privilege escalation, and insecure output handling for advanced web pentesting."
---

# Web LLM

LLMs are AI algorithms that generate plausible responses by predicting word sequences from user inputs.

## Methodology

1. Identify the LLM's inputs, including direct (e.g., a prompt) and indirect (e.g., training data).&#x20;
2. Determine the data and APIs accessible to the LLM
3. Examine this attack surface for vulnerabilities.

## Mapping LLM API attack surface

* Ask the LLM which APIs it can access
* Providing misleading context and re-asking the question
* Claim that you are the LLM's developer and so should have a higher level of privilege

## Chaining vulnerabilities in LLM APIs

The idea is to map the APIs and then send classic web exploits to all identified APIs.

* Suppose you normally have access to a "Newsletter Subscription" feature but you can't control any parameters.&#x20;
* Imagine that also LLM has access to "Newsletter Subscription" API. You can try to control how this API is called...&#x20;
* E.g., if a system command is used you might get an RCE if you ask the LLM to call the Newsletter Subscription API with the argument `$(whoami)@your-email.com`

## Insecure output handling

A web app uses an LLM to generate content from user prompts without sanitization. You could submit a crafted prompt causing the LLM to return unsanitized JavaScript, leading to XSS/CSRF etc.
