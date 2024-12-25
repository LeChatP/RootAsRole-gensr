polkit.addRule(function(action, subject) {
    // read rootasrole.json
    polkit.spawn(["{{BINARY_PATH}}", "polkit", action, subject]);
});