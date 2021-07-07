const Endpoint = '/scopes/status';
const Interval = 1000;
let updateTimeoutId = null;

function updateScopeState() {
    if (updateTimeoutId) {
        clearTimeout(updateTimeoutId);
    }

    updateTimeoutId = setTimeout(() => {
        updateTimeoutId = null;
        fetch(Endpoint)
            .then(response => response.json())
            .then((data) => {
                updateScopes(data.scope);
            })
            .catch((error) => { console.error(error); })
            .finally(() => {
                updateScopeState();
            });
    }, Interval);
}

function updateScopes(scopes) {
    scopes.forEach((scope) => {
        if (scope.state) {
            const scopeId = `${scope.name}_${scope.id}`;
            const scopeEl = document.querySelector(`#${scopeId}`);
            const stateCls = ['state--on', 'state--off'];
            scopeEl.classList.remove(...stateCls);
            const stateClass = `state--${scope.state}`;
            scopeEl.classList.add(stateClass);

            const iconEl = document.querySelector(`#${scopeId} .nav-icon`);
            const iconCls = ['fas', 'far', 'text-danger', 'text-success'];
            iconEl.classList.remove(...iconCls);
            let newIconCls = [];
            if (scope.state === 'on') {
                newIconCls.push('fas', 'text-success');
            } else {
                newIconCls.push('far', 'text-danger');
            }
            iconEl.classList.add(...newIconCls);
        }
        if (scope.scope) {
            // This is a level so we should update all childs
            updateScopes(scope.scope);
        }
    });
}

function unfoldAll() {
    $('#scopes .collapse').collapse('show');
}
