# Contributing Guidelines

## Submitting a pull request

If the PR is not yet ready to be reviewed by the maintainers, ensure it is marked as "Draft". When it is ready, mark it as "Ready for Review".

Before marking a PR as ready for review, ensure:

* Commits are cleanly separated and have useful messages that explain WHAT changed and WHY.
* A changelog entry has been added to CHANGELOG.md under `## Unreleased`.
* Code has been appropriately documented (doc comments, etc.)
* Test coverage is excellent and passes with each signature backend enabled separately.
* Reference related issues with "Closes #N" at the bottom of commit messages.

## AI-assisted contributions policy

The following policy is adapted from the [DNF AI contributions policy](https://github.com/rpm-software-management/dnf5/blob/main/CONTRIBUTING.md) which is in turn adapted from the [the Fedora Council AI-Assisted Contributions Policy](https://docs.fedoraproject.org/en-US/council/policy/ai-contribution-policy/), which was originally authored by Jason Brooks, the Fedora Council, and the Fedora community.

You **MAY** use AI assistance for contributing to this project, as long as you follow the principles described below.

1. **Accountability**:

   You **MUST** take the responsibility for your contribution.

   Contributing to this project means vouching for the quality, license compliance, and utility of your submission.

   All contributions, whether from a human author or assisted by large language models (LLMs) or other generative AI tools, must meet our standards as described in this CONTRIBUTING document.

   The contributor is always the author and is fully accountable for the entirety of these contributions.

   The contributor **MUST** fully review and understand their contribution, and the purpose it serves, prior to submitting.

   Contributions **SHOULD** be solving a clear problem, and be accompanied by tests that exercise the new or changed behavior, if applicable.

2. **Transparency**:

   You **MUST** disclose the use of AI tools when the significant part of the contribution is taken from a tool without changes. You **MUST** use an `Assisted-by: <name of AI tool>` line at the end of your git commit messages to do so, for example:

     * `Assisted-by: generic LLM chatbot`

     * `Assisted-by: ChatGPTv5`

   You **SHOULD** disclose the other uses of AI tools, where it might be useful.

   Routine use of assistive tools for correcting grammar and spelling, or for clarifying language, does not require disclosure.

3. **Contribution & Community Evaluation**:

   AI tools may be used to assist human reviewers by providing analysis and suggestions.

   You **MUST NOT** use AI as the sole or final arbiter in making a substantive or subjective judgment on a contribution.

   The final accountability for accepting a contribution always rests with the human contributor who authorizes the action.
