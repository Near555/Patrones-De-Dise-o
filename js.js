function openTab(evt, tabName) {
    const tabContents = document.getElementsByClassName("tab-content");
    for (let i = 0; i < tabContents.length; i++) {
        tabContents[i].classList.remove("active");
    }
    
    const tabButtons = document.getElementsByClassName("tab-button");
    for (let i = 0; i < tabButtons.length; i++) {
        tabButtons[i].classList.remove("active");
    }
    
    document.getElementById(tabName).classList.add("active");
    evt.currentTarget.classList.add("active");
}

document.addEventListener('DOMContentLoaded', () => {
    // Decorator Section
    const passwordInput = document.getElementById('passwordInput');
    const validateAndHashButton = document.getElementById('validateAndHashButton');
    const validationResultTextarea = document.getElementById('validationResult');
    const hashedPasswordTextarea = document.getElementById('hashedPassword');
    const decoratorErrorMessage = document.getElementById('decoratorErrorMessage');
    
    // Nuevos elementos para el historial
    const decoratorHistoryOutput = document.getElementById('decoratorHistoryOutput');
    const clearDecoratorHistoryButton = document.getElementById('clearDecoratorHistoryButton');
    let decoratorHistory = [];

    async function generateSHA256Hash(text) {
        if (!window.crypto || !window.crypto.subtle) {
            decoratorErrorMessage.textContent = 'Tu navegador no soporta la API Web Crypto necesaria para hashing seguro.';
            decoratorErrorMessage.style.display = 'block';
            return null;
        }
        if (text === null || typeof text !== 'string') {
            decoratorErrorMessage.textContent = 'Error: La entrada para hashing debe ser una cadena de texto.';
            decoratorErrorMessage.style.display = 'block';
            return null;
        }
        if (text.trim() === '') {
            return '';
        }

        try {
            const textEncoder = new TextEncoder();
            const data = textEncoder.encode(text);
            const hashBuffer = await crypto.subtle.digest('SHA-256', data);

            const hashArray = Array.from(new Uint8Array(hashBuffer));
            const hexHash = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
            return hexHash;
        } catch (error) {
            decoratorErrorMessage.textContent = `Error al generar el hash: ${error.message}`;
            decoratorErrorMessage.style.display = 'block';
            console.error('Hashing error:', error);
            return null;
        }
    }

    class PasswordValidator {
        validate(password) {
            if (password.trim() === '') {
                return { isValid: false, message: 'La contraseña no puede estar vacía.' };
            }
            return { isValid: true, message: 'Contraseña Valida.' };
        }
    }

    class ValidatorDecorator {
        constructor(validator) {
            if (!validator || typeof validator.validate !== 'function') {
                throw new Error("El decorador requiere un validador con un método 'validate'.");
            }
            this.validator = validator;
        }

        validate(password) {
            return this.validator.validate(password);
        }
    }

    class MinLengthValidatorDecorator extends ValidatorDecorator {
        constructor(validator, minLength) {
            super(validator);
            if (typeof minLength !== 'number' || minLength < 1) {
                throw new Error("MinLengthValidatorDecorator requiere una longitud mínima válida.");
            }
            this.minLength = minLength;
        }

        validate(password) {
            const result = super.validate(password);
            if (!result.isValid) {
                return result;
            }
            if (password.length < this.minLength) {
                return { isValid: false, message: `La contraseña debe tener al menos ${this.minLength} caracteres.` };
            }
            return result;
        }
    }

    class ContainsNumberValidatorDecorator extends ValidatorDecorator {
        constructor(validator) {
            super(validator);
        }

        validate(password) {
            const result = super.validate(password);
            if (!result.isValid) {
                return result;
            }
            if (!/\d/.test(password)) {
                return { isValid: false, message: 'La contraseña debe contener al menos un número.' };
            }
            return result;
        }
    }

    validateAndHashButton.addEventListener('click', async () => {
        const password = passwordInput.value;
        decoratorErrorMessage.style.display = 'none';
        validationResultTextarea.value = "";
        hashedPasswordTextarea.value = "";
        if (password === null || typeof password !== 'string') {
            decoratorErrorMessage.textContent = 'Error: La entrada de contraseña no es válida.';
            decoratorErrorMessage.style.display = 'block';
            return;
        }
        let validator = new PasswordValidator();
        try {
            validator = new MinLengthValidatorDecorator(validator, 8);
            validator = new ContainsNumberValidatorDecorator(validator);
        } catch (error) {
            decoratorErrorMessage.textContent = `Error al configurar validadores: ${error.message}`;
            decoratorErrorMessage.style.display = 'block';
            console.error('Decorator setup error:', error);
            return;
        }

        const validationResult = validator.validate(password);
        validationResultTextarea.value = validationResult.message;

        let hashed = null;
        if (validationResult.isValid) {
            hashed = await generateSHA256Hash(password);
            if (hashed != null) {
                hashedPasswordTextarea.value = hashed;
            } else {
                hashedPasswordTextarea.value = 'Error al generar hash.';
            }
        } else {
            hashedPasswordTextarea.value = 'No se generó hash: Contraseña inválida.';
        }

        // Crear entrada de historial
        let logEntry;
        if (validationResult.isValid) {
            if (hashed != null) {
                const displayHash = hashed.substring(0, 10) + '...'; // Mostrar primeros 10 caracteres
                logEntry = `[${new Date().toLocaleTimeString()}] Validación exitosa: ${validationResult.message} (Hash: ${displayHash})`;
            } else {
                logEntry = `[${new Date().toLocaleTimeString()}] Error: La contraseña es válida pero falló al generar el hash.`;
            }
        } else {
            logEntry = `[${new Date().toLocaleTimeString()}] Error: ${validationResult.message}`;
        }

        decoratorHistory.push(logEntry);
        decoratorHistoryOutput.value = decoratorHistory.join('\n');
    });

    // Limpiar historial del Decorator
    clearDecoratorHistoryButton.addEventListener('click', () => {
        decoratorHistory = [];
        decoratorHistoryOutput.value = '';
    });

    // Command Section
    const textInput = document.getElementById('textInput');
    const hashCommandButton = document.getElementById('hashCommandButton');
    const clearHistoryButton = document.getElementById('clearHistoryButton');
    const currentHashOutput = document.getElementById('currentHashOutput');
    const historyOutput = document.getElementById('historyOutput');
    const commandErrorMessage = document.getElementById('commandErrorMessage');

    async function generateSHA256HashForCommand(text) {
        if (!window.crypto || !window.crypto.subtle) {
            commandErrorMessage.textContent = 'Tu navegador no soporta la API Web Crypto necesaria para hashing seguro.';
            commandErrorMessage.style.display = 'block';
            return null;
        }
        if (text === null || typeof text !== 'string') {
            commandErrorMessage.textContent = 'Error: La entrada para hashing debe ser una cadena de texto.';
            commandErrorMessage.style.display = 'block';
            return null;
        }
        if (text.trim() === '') {
            return '';
        }
        try {
            const textEncoder = new TextEncoder();
            const data = textEncoder.encode(text);
            const hashBuffer = await crypto.subtle.digest('SHA-256', data);
            const hashArray = Array.from(new Uint8Array(hashBuffer));
            const hexHash = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
            return hexHash;
        } catch (error) {
            commandErrorMessage.textContent = `Error al generar el hash: ${error.message}`;
            commandErrorMessage.style.display = 'block';
            console.error('Hashing error:', error);
            return null;
        }
    }

    class Command {
        execute() {
            throw new Error("El método 'execute' debe ser implementado por subclases.");
        }
    }

    class GenerateHashCommand extends Command {
        constructor(receiver, text) {
            super();
            if (!receiver || typeof receiver.generateHash !== 'function') {
                throw new Error("GenerateHashCommand requiere un receptor con un método 'generateHash'.");
            }
            if (typeof text != 'string') {
                throw new Error("GenerateHashCommand requiere un texto válido.");
            }
            this.receiver = receiver;
            this.text = text;
            this.result = null;
        }

        async execute() {
            this.result = await this.receiver.generateHash(this.text);
            return this.result;
        }

        getLogMessage() {
            if (this.result == null) {
                return `[${new Date().toLocaleTimeString()}] [ERROR] Intentando hashear "${this.text}"`;
            } else if (this.result === '') {
                return `[${new Date().toLocaleTimeString()}] [OK] Hasheado texto vacío: ""`;
            }
            const displayHash = this.result.substring(0, 10) + '....';
            return `[${new Date().toLocaleTimeString()}] [OK] "${this.text}" -> ${displayHash}`;
        }
    }

    class ClearHistoryCommand extends Command {
        constructor(historyManager) {
            super();
            if (!historyManager || typeof historyManager.clearHistory !== 'function') {
                throw new Error("ClearHistoryCommand requiere un gestor de historial con un método 'clearHistory'.");
            }
            this.historyManager = historyManager;
        }

        execute() {
            this.historyManager.clearHistory();
            return true;
        }

        getLogMessage() {
            return `[${new Date().toLocaleTimeString()}] [OK] Historial limpiado.`;
        }
    }

    const HashingService = {
        generateHash: async function(text) {
            return await generateSHA256HashForCommand(text);
        }
    };

    const Invoker = (function() {
        let commandHistory = [];

        return {
            executeCommand: async function(command) {
                if (!command || typeof command.execute !== 'function' || typeof command.getLogMessage !== 'function') {
                    throw new Error("El objeto pasado no es un comando válido.");
                }

                commandErrorMessage.style.display = 'none';
                currentHashOutput.value = "";
                try {
                    const result = await command.execute();
                    commandHistory.push(command.getLogMessage());
                    historyOutput.value = commandHistory.join('\n');
                    return result;
                } catch (error) {
                    commandErrorMessage.textContent = `Error al ejecutar comando: ${error.message}`;
                    commandErrorMessage.style.display = 'block';
                    console.error('Command execution error:', error);
                    return null;
                }
            },
            clearHistory: function() {
                if (commandHistory.length > 0) {
                    commandHistory = [];
                    historyOutput.value = "";
                }
            }
        };
    })();

    hashCommandButton.addEventListener('click', async () => {
        const textToHash = textInput.value;

        if (textToHash.trim() === '') {
            commandErrorMessage.textContent = 'Por favor, introduce texto para generar el hash.';
            commandErrorMessage.style.display = 'block';
            currentHashOutput.value = '';
            return;
        }

        try {
            const hashCommand = new GenerateHashCommand(HashingService, textToHash);
            const hashed = await Invoker.executeCommand(hashCommand);
            if (hashed !== null) {
                currentHashOutput.value = hashed;
            } else {
                currentHashOutput.value = 'Falló la generación del hash.';
            }
        } catch (error) {
            commandErrorMessage.textContent = `Error al preparar comando: ${error.message}`;
            commandErrorMessage.style.display = 'block';
            currentHashOutput.value = '';
            console.error('Command creation error:', error);
        }
    });

    clearHistoryButton.addEventListener('click', () => {
        try {
            const clearCmd = new ClearHistoryCommand(Invoker);
            Invoker.executeCommand(clearCmd);
        } catch (error) {
            commandErrorMessage.textContent = `Error al limpiar historial: ${error.message}`;
            commandErrorMessage.style.display = 'block';
            console.error('Clear history command error:', error);
        }
    });
});