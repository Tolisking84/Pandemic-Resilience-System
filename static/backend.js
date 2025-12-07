let token = "";
let userRole = "";
let searchTimeout = null;
let selectedBuyItem = null;
let allUsers = [];

async function fetchAllUsers() {
    const listResponse = document.getElementById("listResponse");
    try {
        const response = await fetch('/admin/list-users', {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        if (!response.ok) {
            if (response.status === 401 || response.status === 403) {
                window.location.href = '/login';
                return;
            }
            throw new Error(`Failed to fetch users: ${response.status}`);
        }
        allUsers = await response.json();
        console.log('Fetched users:', allUsers);
    } catch (error) {
        console.error('Error fetching users:', error.message);
        allUsers = [];
        if (listResponse) {
            listResponse.innerHTML = `<p>❌ ${error.message}</p>`;
        }
    }
}

function syncTokenFromUrl() {
    const urlParams = new URLSearchParams(window.location.search);
    const urlToken = urlParams.get('token');

    if (urlToken && !localStorage.getItem("token")) {
        console.log("Saving token from URL to localStorage...");
        localStorage.setItem("token", urlToken);
        token = urlToken;
    } else if (urlToken && localStorage.getItem("token") !== urlToken) {
        console.log("Updating token in localStorage from URL...");
        localStorage.setItem("token", urlToken);
        token = urlToken;
    }
}


window.onload = function () {
    syncTokenFromUrl();
    token = localStorage.getItem("token") || "";
    userRole = localStorage.getItem("userRole") || "";
    console.log("Loaded token:", token);
    console.log("Loaded userRole:", userRole);
    localStorage.removeItem("isLoggingIn");
    resetUI();
};

function capitalizeFirst(str) {
    if (!str) return str;
    return str.charAt(0).toUpperCase() + str.slice(1).toLowerCase();
}

// Helper function to capitalize each word
function capitalizeWords(str) {
    if (!str) return str;
    return str
        .split(" ") // Split by spaces
        .map(word => word.charAt(0).toUpperCase() + word.slice(1).toLowerCase()) // Capitalize first letter, lowercase the rest
        .join(" "); // Join back with spaces
}

// Helper function to capitalize specific fields (excluding email)
function formatUserField(label, value) {
    if (label.toLowerCase() === "email") {
        return value; // Don't modify email
    }
    if (label.toLowerCase() === "name") {
        return capitalizeWords(value); // For Name, capitalize after each space
    }
    if (typeof value === "string") {
        // For other fields, capitalize the first letter of each word (if it's not already in a specific format like PRS ID)
        if (label.toLowerCase() === "prs id" || label.toLowerCase() === "user id" || label.toLowerCase() === "merchant id") {
            return value; // Don't modify IDs
        }
        if (label.toLowerCase() === "date of birth") {
            return value; // Don't modify date format
        }
        return capitalizeWords(value);
    }
    return value || "N/A";
}

function isValidEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

function showNotification(message, type) {
    const notification = document.getElementById("notification");
    if (notification) {
        notification.innerText = message;
        notification.className = `notification show ${type}`; // Add 'show' to display and type for styling
        setTimeout(() => {
            notification.className = "notification"; // Hide after 3 seconds
        }, 3000);
    } else {
        console.warn("Notification element not found in DOM");
    }
}

function login(event) {
    event.preventDefault();
    console.log("Login attempt started...");

    const emailInput = document.getElementById("email");
    const passwordInput = document.getElementById("password");
    const email = emailInput.value.trim();
    const password = passwordInput.value.trim();

    if (!email || !isValidEmail(email) || !password) {
        showNotification("❌ Please enter a valid email and password.", "error");
        return;
    }

    fetch("/user-authentication", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password }),
    })
    .then(response => {
        console.log("Response status:", response.status);
        if (!response.ok) {
            if (response.status === 400) {
                showNotification("❌ Missing email or password.", "error");
            } else if (response.status === 401) {
                showNotification("❌ Invalid credentials.", "error");
            } else if (response.status === 403) {
                showNotification("❌ User account is inactive.", "error");
            }
            throw new Error(`Login failed with status: ${response.status}`);
        }
        return response.json();
    })
    .then(data => {
        console.log("Login response:", data);
        token = data.token;
        userRole = data.role;
        localStorage.setItem("token", token);
        localStorage.setItem("userRole", userRole);
        console.log("Stored token:", token); // Debug log
        console.log("Stored userRole:", userRole); // Debug log
        showNotification("✅ Login successful! Redirecting...", "success");
        setTimeout(() => {
            if (userRole === "public") {
                window.location.href = `/public?token=${encodeURIComponent(token)}`;
            } else if (userRole === "merchant") {
                window.location.href = `/merchant?token=${encodeURIComponent(token)}`;
            } else if (userRole === "government") {
                window.location.href = `/admin?token=${encodeURIComponent(token)}`;
            }
        }, 1000);
    })
    .catch(error => {
        console.error("Login error:", error.message);
        showNotification(`❌ Login failed: ${error.message}`, "error");
    });
}

function register() {
    const firstName = document.getElementById("regFirstName").value.trim();
    const lastName = document.getElementById("regLastName").value.trim();
    const dob = document.getElementById("regDob").value;
    const email = document.getElementById("regEmail").value.trim();
    const password = document.getElementById("regPassword").value.trim();
    const role = document.getElementById("regRole").value;
    const notification = document.getElementById("notification");

    if (!firstName || !lastName || !dob || !email || !isValidEmail(email) || !password || !role) {
        notification.innerText = "❌ Please fill in all required fields.";
        notification.className = "notification error show";
        return;
    }    

    const userData = { 
        first_name: firstName, 
        last_name: lastName, 
        dob, 
        email, 
        password, 
        role 
    };

    fetch("/register", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify(userData),
    })
    .then(response => {
        return response.json().then(data => ({ status: response.status, data }));
    })
    .then(({ status, data }) => {
        if (status === 201) {
            notification.innerText = `✅ ${data.message}\nPRS ID: ${data.prs_id}\nRedirecting to login...`;
            notification.className = "notification success show";
            setTimeout(() => {
                window.location.href = "/login";
            }, 2000);
        } else {
            throw new Error(data.message || `Status: ${status}`);
        }
    })
    .catch(error => {
        notification.innerText = `❌ ${error.message}`;
        notification.className = "notification error show";
    });
}


function logout() {
    fetch("/logout", {
        method: "POST",
        headers: { "Authorization": `Bearer ${token}` },
    })
        .then(() => {
            token = "";
            userRole = "";
            localStorage.clear();
            window.location.href = "/login";
        })
        .catch(error => {
            console.error("Logout error:", error);
            token = "";
            userRole = "";
            localStorage.clear();
            window.location.href = "/login";
        });
}

async function fetchInventory() {
    try {
        const response = await fetch("/user-inventory", {
            method: "GET",
            headers: { "Authorization": `Bearer ${token}` },
        });
        if (!response.ok) {
            if (response.status === 403 || response.status === 401) {
                console.error("Unauthorized access, token may be invalid");
                const inventoryDisplay = document.getElementById("inventoryDisplay");
                if (inventoryDisplay) {
                    inventoryDisplay.innerText = "❌ Please log in again to view inventory.";
                }
                return;
            }
            throw new Error(`Status: ${response.status}`);
        }
        const data = await response.json();
        const inventoryDisplay = document.getElementById("inventoryDisplay");
        const inventoryTitle = document.getElementById("inventoryTitle");
        const totalValueDisplay = document.getElementById("totalValue");
        const vaccinationDisplay = document.getElementById("vaccinationDisplay");
        const prsIdDisplay = document.getElementById("prsIdDisplay");
        const itemSelect = document.getElementById("itemName");
        const removeItemSelect = document.getElementById("removeItemName");

        if (inventoryDisplay && inventoryTitle) {
            if (userRole === "merchant") {
                const items = data.items || [];
                const itemCount = items.length;
                inventoryTitle.innerText = `Your Inventory${itemCount > 0 ? ` (${itemCount} ${itemCount === 1 ? 'item' : 'items'})` : ''}`;
                inventoryDisplay.innerText = items.length > 0
                    ? "Current Inventory:\n" + items.map(item => `${item.name}: ${item.stock} (Price: $${item.price ? item.price.toFixed(2) : 'N/A'})`).join("\n")
                    : "No inventory items yet. Add items below.";
                if (totalValueDisplay) {
                    const totalValue = items.reduce((sum, item) => {
                        const price = item.price || 0;
                        return sum + (item.stock * price);
                    }, 0);
                    totalValueDisplay.innerText = `$${totalValue.toFixed(2)}`;
                }
            } else {
                inventoryTitle.innerText = "Your Inventory";
                inventoryDisplay.innerText = data.message || "No inventory data.";
                if (totalValueDisplay) {
                    totalValueDisplay.innerText = "$0.00";
                }
            }
        }

        if (vaccinationDisplay) {
            vaccinationDisplay.innerText = data.vaccination 
                ? `Status: ${data.vaccination.status}\nDate: ${data.vaccination.date}\nType: ${data.vaccination.vaccine_type}`
                : "No vaccination records available.";
        }

        if (prsIdDisplay) {
            prsIdDisplay.innerText = `PRS ID: ${data.prs_id}\n` + 
                                    (data.pdf ? `Uploaded PDF: ${data.pdf.filename} (ID: ${data.pdf.pdf_id})` : "No PDF uploaded.");
        }

        if (itemSelect && removeItemSelect) {
            while (itemSelect.options.length > 1) {
                itemSelect.remove(1);
            }
            while (removeItemSelect.options.length > 1) {
                removeItemSelect.remove(1);
            }

            if (data.items && data.items.length > 0) {
                data.items.forEach(item => {
                    const option1 = document.createElement("option");
                    option1.value = item.name;
                    option1.text = `${item.name} (Stock: ${item.stock}, Price: $${item.price ? item.price.toFixed(2) : 'N/A'})`;
                    itemSelect.appendChild(option1);

                    const option2 = document.createElement("option");
                    option2.value = item.name;
                    option2.text = `${item.name} (Stock: ${item.stock}, Price: $${item.price ? item.price.toFixed(2) : 'N/A'})`;
                    removeItemSelect.appendChild(option2);
                });
            }
        }
    } catch (error) {
        console.error("Fetch inventory error:", error.message);
        const inventoryDisplay = document.getElementById("inventoryDisplay");
        const inventoryTitle = document.getElementById("inventoryTitle");
        const totalValueDisplay = document.getElementById("totalValue");
        if (inventoryDisplay) inventoryDisplay.innerText = "❌ Error fetching inventory: " + error.message;
        if (inventoryTitle) inventoryTitle.innerText = "Your Inventory";
        if (totalValueDisplay) totalValueDisplay.innerText = "$0.00";
    }
}

function uploadVaccinationPdf() {
    if (!token) {
        console.error("No token found, redirecting to login");
        window.location.href = '/login';
        return;
    }

    const fileInput = document.getElementById("pdfFile");
    const pdfUploadResponse = document.getElementById("pdfUploadResponse");
    const file = fileInput.files[0];

    if (!file) {
        pdfUploadResponse.innerText = "❌ Please select a file.";
        return;
    }

    const formData = new FormData();
    formData.append("file", file);

    fetch("/upload-vaccination-pdf", {
        method: "POST",
        headers: { "Authorization": `Bearer ${token}` },
        body: formData,
    })
    .then(response => {
        if (!response.ok) {
            if (response.status === 401 || response.status === 403) {
                console.error("Unauthorized, redirecting to login");
                window.location.href = '/login';
                return;
            }
            return response.json().then(errorData => {
                throw new Error(errorData.message || `Status: ${response.status}`);
            });
        }
        return response.json();
    })
    .then(data => {
        pdfUploadResponse.innerText = `✅ ${data.message}`;
        fetchInventory(); // Refresh inventory to update PDF records
    })
    .catch(error => {
        pdfUploadResponse.innerText = `❌ ${error.message}`;
    });
}

function updateStock() {
    const itemName = document.getElementById("itemName").value;
    const stock = document.getElementById("stock").value;
    const price = document.getElementById("price").value;
    const responseDisplay = document.getElementById("response");
    const limit = document.getElementById("limit").value;

    if (!itemName || !stock) {
        responseDisplay.innerText = "❌ Please select an item and provide stock quantity.";
        return;
    }

    const payload = { item_name: itemName, stock: parseInt(stock) };
    if (price) payload.price = parseFloat(price);
    if (limit) payload.limit = parseInt(limit);

    fetch("/update-stock", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify(payload),
    })
        .then(response => {
            if (!response.ok) {
                if (response.status === 403 || response.status === 401) {
                    window.location.href = "/login";
                    return;
                }
                return response.json().then(errorData => {
                    throw new Error(errorData.message || `Status: ${response.status}`);
                });
            }
            return response.json();
        })
        .then(data => {
            responseDisplay.innerText = `✅ ${data.message}`;
            fetchInventory();
        })
        .catch(error => {
            responseDisplay.innerText = `❌ ${error.message}`;
        });
}

function addInventoryItem() {
    const newItemName = document.getElementById("newItemName").value.trim();
    const newItemStock = document.getElementById("newItemStock").value;
    const newItemPrice = document.getElementById("newItemPrice").value;
    const newItemLimit = document.getElementById("newItemLimit").value;
    const responseDisplay = document.getElementById("response");

    if (!newItemName || !newItemStock) {
        responseDisplay.innerText = "❌ Please provide new item name and initial stock quantity.";
        return;
    }

    const payload = { item_name: newItemName, stock: parseInt(newItemStock) };
    if (newItemPrice) payload.price = parseFloat(newItemPrice);
    if (newItemLimit) payload.limit = parseInt(newItemLimit);
    console.log("Adding new item with payload:", payload);

    fetch("/add-item", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify(payload),
    })
        .then(response => {
            console.log("Add item response status:", response.status);
            if (!response.ok) {
                if (response.status === 403 || response.status === 401) {
                    console.error("Unauthorized, redirecting to login");
                    window.location.href = "/login";
                    return;
                }
                return response.json().then(errorData => {
                    throw new Error(errorData.message || `Status: ${response.status}`);
                });
            }
            return response.json();
        })
        .then(data => {
            console.log("Add item response:", data);
            responseDisplay.innerText = `✅ ${data.message}`;
            fetchInventory();
        })
        .catch(error => {
            console.error("Add item error:", error.message);
            responseDisplay.innerText = `❌ ${error.message}`;
        });
}

function removeInventoryItem() {
    const itemName = document.getElementById("removeItemName").value;
    const responseDisplay = document.getElementById("response");

    if (!itemName) {
        responseDisplay.innerText = "❌ Please select an item to remove.";
        return;
    }

    fetch("/remove-item", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ item_name: itemName }),
    })
        .then(response => {
            if (!response.ok) {
                if (response.status === 403 || response.status === 401) {
                    window.location.href = "/login";
                    return;
                }
                return response.json().then(errorData => {
                    throw new Error(errorData.message || `Status: ${response.status}`);
                });
            }
            return response.json();
        })
        .then(data => {
            responseDisplay.innerText = `✅ ${data.message}`;
            fetchInventory();
        })
        .catch(error => {
            responseDisplay.innerText = `❌ ${error.message}`;
        });
}

function batchUpdateStock() {
    const batchUpdateInput = document.getElementById("batchUpdate").value.trim();
    const responseDisplay = document.getElementById("response");

    let batchData;
    try {
        batchData = JSON.parse(batchUpdateInput);
        if (!Array.isArray(batchData)) {
            throw new Error("Input must be a JSON array.");
        }
        for (const item of batchData) {
            if (!item.item_name || typeof item.stock !== "number") {
                throw new Error("Each item must have an item_name and stock (number).");
            }
            if (item.price !== undefined && typeof item.price !== "number") {
                throw new Error("Price must be a number if provided.");
            }
        }
    } catch (error) {
        responseDisplay.innerText = `❌ Invalid JSON format: ${error.message}`;
        return;
    }

    fetch("/batch-update-stock", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ items: batchData }),
    })
        .then(response => {
            if (!response.ok) {
                if (response.status === 403 || response.status === 401) {
                    window.location.href = "/login";
                    return;
                }
                return response.json().then(errorData => {
                    throw new Error(errorData.message || `Status: ${response.status}`);
                });
            }
            return response.json();
        })
        .then(data => {
            responseDisplay.innerText = `✅ ${data.message}`;
            fetchInventory();
        })
        .catch(error => {
            responseDisplay.innerText = `❌ ${error.message}`;
        });
}

function findItems() {
    const itemName = document.getElementById("itemSearch").value.trim();
    const itemSearchResponse = document.getElementById("itemSearchResponse");

    if (!itemName) {
        itemSearchResponse.innerText = "❌ Please provide an item name.";
        return;
    }

    fetch("/search-items", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ item_name: itemName }),
    })
        .then(response => {
            if (!response.ok) {
                if (response.status === 403 || response.status === 401) {
                    window.location.href = "/login";
                    return;
                }
                return response.json().then(errorData => {
                    throw new Error(errorData.message || `Status: ${response.status}`);
                });
            }
            return response.json();
        })
        .then(data => {
            if (data.results.length === 0) {
                itemSearchResponse.innerText = "No items found.";
            } else {
                itemSearchResponse.innerHTML = "<h3>Search Results:</h3><ul>" + 
                    data.results.map(item => `<li>${item.item_name}: ${item.stock} (Price: $${item.price ? item.price.toFixed(2) : 'N/A'}) at Merchant ${item.merchant_id}</li>`).join("") + 
                    "</ul>";
            }
        })
        .catch(error => {
            itemSearchResponse.innerText = `❌ ${error.message}`;
        });
}

function createUser() {
    const firstName = document.getElementById("createFirstName")?.value.trim();
    const lastName = document.getElementById("createLastName")?.value.trim();
    const dob = document.getElementById("createDob")?.value;
    const email = document.getElementById("createEmail")?.value.trim();
    const password = document.getElementById("createPassword")?.value.trim();
    const role = document.getElementById("createRole")?.value;
    const createResponse = document.getElementById("createResponse");

    if (!createResponse) {
        console.error("createResponse element not found");
        return;
    }

    if (!firstName || !lastName || !dob || !email || !isValidEmail(email) || !password || !role) {
        createResponse.innerText = "❌ Please fill in all required fields.";
        return;
    }

    const userData = { first_name: firstName, last_name: lastName, dob, email, password, role };

    fetch("/admin/create-user", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify(userData),
    })
        .then(response => {
            if (!response.ok) {
                if (response.status === 403 || response.status === 401) {
                    window.location.href = "/login";
                    return;
                }
                return response.json().then(errorData => {
                    throw new Error(errorData.message || `Status: ${response.status}`);
                });
            }
            return response.json();
        })
        .then(data => {
            createResponse.innerText = `✅ ${data.message}\nPRS ID: ${data.prs_id}`;
            listUsers(); // Refresh the user list after creating a new user
        })
        .catch(error => {
            createResponse.innerText = `❌ ${error.message}`;
        });
}

function toggleMerchantIdField() {
    const role = document.getElementById("createRole").value;
    const merchantIdGroup = document.getElementById("merchantIdGroup");
    merchantIdGroup.style.display = role === "merchant" ? "block" : "none";
}

function deleteUser() {
    const email = document.getElementById("deleteEmail").value.trim();
    const deleteResponse = document.getElementById("deleteResponse");

    if (!email || !isValidEmail(email)) {
        deleteResponse.innerText = "❌ Please provide a valid email.";
        return;
    }

    fetch("/admin/delete-user", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ email }),
    })
        .then(response => {
            if (!response.ok) {
                if (response.status === 403 || response.status === 401) {
                    window.location.href = "/login";
                    return;
                }
                return response.json().then(errorData => {
                    throw new Error(errorData.message || `Status: ${response.status}`);
                });
            }
            return response.json();
        })
        .then(data => {
            deleteResponse.innerText = `✅ ${data.message}`;
            listUsers(); // Refresh the user list after deletion
        })
        .catch(error => {
            deleteResponse.innerText = `❌ ${error.message}`;
        });
}

function listUsers() {
    const listResponse = document.getElementById("listResponse");
    fetch("/admin/list-users", {
        method: "GET",
        headers: { "Authorization": `Bearer ${token}` },
    })
        .then(response => {
            if (!response.ok) {
                if (response.status === 403 || response.status === 401) {
                    window.location.href = "/login";
                    return;
                }
                return response.json().then(errorData => {
                    throw new Error(errorData.message || `Status: ${response.status}`);
                });
            }
            return response.json();
        })
        .then(users => {
            if (users.length === 0) {
                listResponse.innerHTML = "<p>No users found.</p>";
                return;
            }
            listResponse.innerHTML = "" + 
                users.map(user => {
                    const name = (user.first_name || user.last_name) 
                        ? `${user.first_name || ''} ${user.last_name || ''}`.trim() 
                        : "No Name";
                    return `<li>
                        <span class="user-info">${name} - ${user.email}</span>
                        <button class="details-btn" onclick='showUserDetails(${JSON.stringify(user)})'>Details</button>
                    </li>`;
                }).join("") + 
                "</ul>";
        })
        .catch(error => {
            listResponse.innerHTML = `<p>❌ ${error.message}</p>`;
        });
}

function listStocks() {
    const stockListResponse = document.getElementById('stockListResponse');
    fetch('/admin/list-stocks', {
        headers: { 'Authorization': `Bearer ${token}` }
    })
    .then(response => {
        if (!response.ok) {
            throw new Error(`Failed to fetch stocks: ${response.status}`);
        }
        return response.json();
    })
    .then(data => {
        let html = '<ul class="stock-list">';
        data.forEach(stock => {
            const merchantId = stock.merchant_id;
            const merchantUser = allUsers.find(u => u.merchant_id === merchantId) || {};
            const merchantName = `${merchantUser.first_name || 'N/A'} ${merchantUser.last_name || ''}`.trim();
            const merchantEmail = merchantUser.email || 'N/A';
            const items = stock.items || [];
            items.forEach(item => {
                html += `
                    <li>
                        <span class="user-info">${item.name} - Stock: ${item.stock}</span>
                        <button class="details-btn" onclick='showStockDetails(${JSON.stringify(item)}, "${merchantId}")'>Details</button>
                    </li>
                `;
            });
        });
        html += '</ul>';
        stockListResponse.innerHTML = html;
    })
    .catch(error => {
        stockListResponse.innerHTML = `<p>❌ Failed to load stocks: ${error.message}</p>`;
    });
}


function showStockDetails(item, merchantId) {
    const merchantUser = allUsers.find(u => u.merchant_id === merchantId) || {};
    const merchantName = `${merchantUser.first_name || 'N/A'} ${merchantUser.last_name || ''}`.trim();
    const merchantEmail = merchantUser.email || 'N/A';

    const modal = document.getElementById("userDetailsModal");
    const modalContent = document.getElementById("modalUserDetails");

    modalContent.innerHTML = `
        <p><strong>Item:</strong> ${item.name}</p>
        <p><strong>Stock:</strong> ${item.stock}</p>
        <p><strong>Price:</strong> $${item.price !== undefined ? item.price.toFixed(2) : 'N/A'}</p>
        <p><strong>Limit:</strong> ${item.limit || 'No limit'}</p>
        <hr>
        <p><strong>Merchant ID:</strong> ${merchantId}</p>
        <p><strong>Merchant Name:</strong> ${merchantName}</p>
        <p><strong>Merchant Email:</strong> ${merchantEmail}</p>
    `;

    modal.style.display = "block";
}


function searchStocks() {
    const query = document.getElementById('searchStock').value.toLowerCase();
    const listItems = document.querySelectorAll('#stockListResponse li');

    listItems.forEach(item => {
        const text = item.innerText.toLowerCase();
        item.style.display = text.includes(query) ? '' : 'none';
    });
}



















function showUserDetails(user) {
    const modal = document.getElementById("userDetailsModal");
    const modalContent = document.getElementById("modalUserDetails");
    const name = (user.first_name || user.last_name) 
        ? `${user.first_name || ''} ${user.last_name || ''}`.trim() 
        : "No Name";

    // Format the fields with capitalization
    modalContent.innerHTML = `
        <p><strong>Name:</strong> ${formatUserField("name", name)}</p>
        <p><strong>Email:</strong> ${formatUserField("email", user.email)}</p>
        <p><strong>Role:</strong> ${formatUserField("role", user.role)}</p>
        <p><strong>User ID:</strong> ${formatUserField("user id", user.user_id)}</p>
        <p><strong>PRS ID:</strong> ${formatUserField("prs id", user.prs_id)}</p>
        <p><strong>Date Of Birth:</strong> ${formatUserField("date of birth", user.dob)}</p>
        <p><strong>Status:</strong> ${formatUserField("status", user.status)}</p>
        ${user.merchant_id ? `<p><strong>Merchant ID:</strong> ${formatUserField("merchant id", user.merchant_id)}</p>` : ''}
    `;

    modal.style.display = "block";

    const closeBtn = modal.querySelector(".close");
    closeBtn.onclick = function() {
        modal.style.display = "none";
    };

    window.onclick = function(event) {
        if (event.target === modal) {
            modal.style.display = "none";
        }
    };
}

function addVaccination() {
    const userId = document.getElementById("vaccinationUserId").value.trim();
    const status = document.getElementById("vaccinationStatus").value.trim().toLowerCase(); // Normalize to lowercase
    const date = document.getElementById("vaccinationDate").value;
    const vaccineType = document.getElementById("vaccineType").value.trim();
    const vaccinationResponse = document.getElementById("vaccinationResponse");

    if (!userId || !status || !date || !vaccineType) {
        vaccinationResponse.innerText = "❌ Please fill in all fields.";
        return;
    }

    fetch("/admin/add-vaccination", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ user_id: userId, status, date, vaccine_type: vaccineType }),
    })
        .then(response => {
            if (!response.ok) {
                if (response.status === 403 || response.status === 401) {
                    window.location.href = "/login";
                    return;
                }
                return response.json().then(errorData => {
                    throw new Error(errorData.message || `Status: ${response.status}`);
                });
            }
            return response.json();
        })
        .then(data => {
            vaccinationResponse.innerText = `✅ ${data.message}`;
        })
        .catch(error => {
            vaccinationResponse.innerText = `❌ ${error.message}`;
        });
}

async function fetchVaccinationRequestStatus() {
    const tableBody = document.getElementById('vaccinationRequestTableBody');
    tableBody.innerHTML = '<tr><td colspan="4">Loading...</td></tr>';

    try {
        const token = localStorage.getItem('token');
        if (!token) {
            tableBody.innerHTML = '<tr><td colspan="4">Please log in to view vaccination request status.</td></tr>';
            return;
        }

        const response = await fetch('/public/vaccination-request-status', {
            method: 'GET',
            headers: { 'Authorization': `Bearer ${token}` }
        });

        if (!response.ok) {
            if (response.status === 401 || response.status === 403) {
                tableBody.innerHTML = '<tr><td colspan="4">Unauthorized: Please log in again.</td></tr>';
                setTimeout(() => { window.location.href = '/login'; }, 2000);
                return;
            }
            const errorData = await response.json();
            throw new Error(errorData.message || `HTTP error: ${response.status}`);
        }

        const requests = await response.json();
        tableBody.innerHTML = '';

        if (requests.length === 0) {
            tableBody.innerHTML = '<tr><td colspan="4">No vaccination requests found.</td></tr>';
            return;
        }

        requests.forEach(vaccination => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${vaccination.request_id}</td>
                <td>${vaccination.vaccine_type || 'N/A'}</td>
                <td>${capitalizeFirst(vaccination.status) || 'Pending'}</td>
                <td><button class="btn btn-primary" onclick='showVaccinationRequestDetails(${JSON.stringify(vaccination)})'>Details</button></td>
            `;
            tableBody.appendChild(row);
        });
    } catch (error) {
        console.error('Error fetching vaccination request status:', error);
        tableBody.innerHTML = `<tr><td colspan="4">Error loading data: ${error.message}</td></tr>`;
    }
}

function showVaccinationRequestDetails(vaccination) {
    const modal = document.getElementById('vaccinationDetailsModal');
    const modalContent = document.querySelector('#vaccinationDetailsModal .modal-content');

    if (!modal || !modalContent) {
        console.error('Modal or modal content not found in the DOM');
        return;
    }

    // Populate modal content
    modalContent.innerHTML = `
        <span class="close">×</span>
        <h2>Vaccination Request Details</h2>
        <p><strong>Request ID:</strong> <span id="modalRequestId">${vaccination.request_id || vaccination._id || 'N/A'}</span></p>
        <p><strong>Vaccine Type:</strong> <span id="modalVaccineType">${vaccination.vaccine_type || 'N/A'}</span></p>
        <p><strong>Status:</strong> <span id="modalStatus">${capitalizeFirst(vaccination.status) || 'Pending'}</span></p>
        <p><strong>Date:</strong> <span id="modalDate">${vaccination.date || 'N/A'}</span></p>
        <p><strong>Admin Response:</strong> <span id="modalAdminResponse">${vaccination.admin_response || 'No notes available'}</span></p>
        ${vaccination.status.toLowerCase() === 'approved' ? `<button class="btn btn-primary" onclick='generateVaccinationPDF("${vaccination.request_id || vaccination._id}")'>Download PDF</button>` : ''}
    `;

    modal.style.display = 'block';

    const closeBtn = modal.querySelector('.close');
    if (closeBtn) {
        closeBtn.onclick = function() {
            modal.style.display = 'none';
        };
    }

    window.onclick = function(event) {
        if (event.target === modal) {
            modal.style.display = 'none';
        }
    };
}

// Generate Vaccination PDF
function generateVaccinationPDF(requestId) {
    if (!token) {
        console.error("No token, redirecting to login");
        window.location.href = '/login';
        return;
    }

    if (!requestId || !/^[0-9a-f]{24}$/i.test(requestId)) {
        console.error("Invalid request ID");
        return;
    }

    fetch(`/generate-vaccination-pdf/${requestId}`, {
        method: 'GET',
        headers: { "Authorization": `Bearer ${token}` },
    })
    .then(response => {
        if (!response.ok) {
            if (response.status === 401 || response.status === 403) {
                console.error("Unauthorized, redirecting to login");
                window.location.href = '/login';
                return null;
            }
            // Try to parse JSON, but handle non-JSON responses
            return response.text().then(text => {
                try {
                    const errorData = JSON.parse(text);
                    throw new Error(errorData.message || `HTTP ${response.status}`);
                } catch {
                    throw new Error(`Server error: ${response.status}`);
                }
            });
        }
        return response.blob();
    })
    .then(blob => {
        if (!blob) return; // Handle redirect case
        const pdfUrl = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = pdfUrl;
        link.download = `vaccination_certificate_${requestId}.pdf`;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        URL.revokeObjectURL(pdfUrl);
        console.log("PDF downloaded successfully");
    })
    .catch(error => {
        console.error("PDF generation error:", error.message);
    });
}

function capitalizeFirst(string) {
    if (!string) return '';
    return string.charAt(0).toUpperCase() + string.slice(1).toLowerCase();
}

function clearVaccinationRequests() {
    const pdfUploadResponse = document.getElementById("pdfUploadResponse");
    const tableBody = document.getElementById("vaccinationRequestTableBody");

    fetch("/public/clear-vaccination-requests", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "Authorization": `Bearer ${token}`,
        },
    })
        .then(response => {
            if (!response.ok) {
                if (response.status === 403 || response.status === 401) {
                    window.location.href = "/login";
                    return;
                }
                return response.json().then(errorData => {
                    throw new Error(errorData.message || `Status: ${response.status}`);
                });
            }
            return response.json();
        })
        .then(data => {
            pdfUploadResponse.innerText = `✅ ${data.message}`;
            // Clear the table immediately
            tableBody.innerHTML = '<tr><td colspan="4">No vaccination requests found.</td></tr>';
        })
        .catch(error => {
            pdfUploadResponse.innerText = `❌ ${error.message}`;
        });
}

function listAllVaccinationRequests() {
    const allVaccinationRequestsList = document.getElementById("allVaccinationRequestsList");
    fetch("/admin/list-all-vaccination-requests", {
        method: "GET",
        headers: { "Authorization": `Bearer ${token}` },
    })
    .then(response => {
        if (!response.ok) {
            if (response.status === 403 || response.status === 401) {
                window.location.href = "/login";
                return;
            }
            return response.json().then(errorData => {
                throw new Error(errorData.message || `Status: ${response.status}`);
            });
        }
        return response.json();
    })
    .then(requests => {
        if (requests.length === 0) {
            allVaccinationRequestsList.innerHTML = "<p>No vaccination requests found.</p>";
            return;
        }

        // Group requests by user_id
        const groupedRequests = {};
        requests.forEach(req => {
            const key = `${req.user_id}-${req.first_name}-${req.last_name}`;
            if (!groupedRequests[key]) {
                groupedRequests[key] = {
                    user_id: req.user_id,
                    first_name: req.first_name,
                    last_name: req.last_name,
                    requests: []
                };
            }
            groupedRequests[key].requests.push(req);
        });

        // Render grouped UI
        let html = "<h3>All Vaccination Requests:</h3>";
        Object.values(groupedRequests).forEach(group => {
            const name = (group.first_name || group.last_name) 
                ? `${group.first_name || ''} ${group.last_name || ''}`.trim() 
                : "No Name";
            html += `
                <div class="user-group">
                    <h4>User: ${name} (ID: ${group.user_id})</h4>
                    <button class="btn btn-primary toggle-requests" data-user="${group.user_id}">Show Requests (${group.requests.length})</button>
                    <ul class="request-list" id="requests-${group.user_id}" style="display: none;">
                        ${group.requests.map(req => `
                            <li>
                                <span class="user-info">Vaccine: ${req.vaccine_type} (Status: ${capitalizeFirst(req.status)}, Requested on: ${req.date})</span>
                                <div class="form-group">
                                    <label for="adminResponse-${req.request_id}">Response Note</label>
                                    <input id="adminResponse-${req.request_id}" class="form-control" placeholder="Optional note" value="${req.admin_response || ''}">
                                </div>
                                <select id="status-${req.request_id}" class="form-control">
                                    <option value="Pending" ${req.status === 'Pending' ? 'selected' : ''}>Pending</option>
                                    <option value="Approved" ${req.status === 'Approved' ? 'selected' : ''}>Approved</option>
                                    <option value="Rejected" ${req.status === 'Rejected' ? 'selected' : ''}>Rejected</option>
                                </select>
                                <button class="btn btn-primary" onclick='updateVaccinationStatus("${req.request_id}")'>Update Status</button>
                            </li>
                        `).join("")}
                    </ul>
                </div>
            `;
        });
        allVaccinationRequestsList.innerHTML = html;

        // Add event listeners for toggle buttons
        document.querySelectorAll('.toggle-requests').forEach(button => {
            button.addEventListener('click', () => {
                const userId = button.getAttribute('data-user');
                const requestList = document.getElementById(`requests-${userId}`);
                const isHidden = requestList.style.display === 'none';
                requestList.style.display = isHidden ? 'block' : 'none';
                button.textContent = isHidden ? `Hide Requests (${button.textContent.match(/\d+/)[0]})` : `Show Requests (${button.textContent.match(/\d+/)[0]})`;
            });
        });
    })
    .catch(error => {
        allVaccinationRequestsList.innerHTML = `<p>❌ ${error.message}</p>`;
    });
}

function updateVaccinationStatus(requestId) {
    const adminResponse = document.getElementById(`adminResponse-${requestId}`).value.trim();
    const newStatus = document.getElementById(`status-${requestId}`).value;
    const allVaccinationRequestsList = document.getElementById("allVaccinationRequestsList");

    fetch("/admin/update-vaccination-status", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ request_id: requestId, status: newStatus, admin_response: adminResponse }),
    })
        .then(response => {
            if (!response.ok) {
                if (response.status === 403 || response.status === 401) {
                    window.location.href = "/login";
                    return;
                }
                return response.json().then(errorData => {
                    throw new Error(errorData.message || `Status: ${response.status}`);
                });
            }
            return response.json();
        })
        .then(data => {
            allVaccinationRequestsList.innerHTML = `<p>✅ ${data.message}</p>`;
            listAllVaccinationRequests(); // Refresh the list
        })
        .catch(error => {
            allVaccinationRequestsList.innerHTML = `<p>❌ ${error.message}</p>`;
        });
}

function closeModal(modalId) {
    const modal = document.getElementById(modalId);
    modal.style.display = 'none';
}

function showMerchantDetails(merchant) {
    const modal = document.getElementById("userDetailsModal");
    const modalContent = document.getElementById("modalUserDetails");

    const merchantName = `${merchant.user.first_name || ''} ${merchant.user.last_name || ''}`.trim();
    const email = merchant.user.email || 'N/A';
    const merchantId = merchant.merchant_id || 'N/A';

    let itemsList = "No items.";
    if (merchant.items && merchant.items.length > 0) {
        itemsList = merchant.items.map(item => `${item.name}: ${item.stock} units (Price: $${item.price ? item.price.toFixed(2) : 'N/A'})`).join("<br>");
    }

    modalContent.innerHTML = `
        <p><strong>Merchant Name:</strong> ${merchantName}</p>
        <p><strong>Email:</strong> ${email}</p>
        <p><strong>Merchant ID:</strong> ${merchantId}</p>
        <p><strong>Items:</strong><br>${itemsList}</p>
    `;

    modal.style.display = "block";

    const closeBtn = modal.querySelector(".close");
    closeBtn.onclick = function() {
        modal.style.display = "none";
    };

    window.onclick = function(event) {
        if (event.target === modal) {
            modal.style.display = "none";
        }
    };
}


function fetchAdminStats() {
    fetch('/admin/statistics', {
        method: 'GET',
        headers: { "Authorization": `Bearer ${token}` },
    })
    .then(response => {
        if (!response.ok) {
            if (response.status === 403 || response.status === 401) {
                console.error('Unauthorized access, token may be invalid');
                document.getElementById('adminCount').textContent = 'Error';
                document.getElementById('merchantCount').textContent = 'Error';
                document.getElementById('userCount').textContent = 'Error';
                document.getElementById('vaccinationRate').textContent = 'Error';
                return;
            }
            throw new Error(`Status: ${response.status}`);
        }
        return response.json();
    })
    .then(data => {
        console.log('Admin stats received:', data);
        document.getElementById('adminCount').textContent = data.admins || 0;
        document.getElementById('merchantCount').textContent = data.merchants || 0;
        document.getElementById('userCount').textContent = data.users || 0;
        // Format vaccination rate to 2 decimal places
        document.getElementById('vaccinationRate').textContent = `${(data.vaccination_rate || 0).toFixed(2)}%`;

        const statsChartCanvas = document.getElementById('statsChart');
        if (statsChartCanvas && statsChartCanvas.chart) {
            statsChartCanvas.chart.destroy();
        }

        const ctx = statsChartCanvas.getContext('2d');
        statsChartCanvas.chart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: ['Admins', 'Merchants', 'Users'],
                datasets: [{
                    label: 'User Counts',
                    data: [data.admins || 0, data.merchants || 0, data.users || 0],
                    backgroundColor: ['#1e3a8a', '#10b981', '#6b7280']
                }]
            },
            options: {
                scales: {
                    y: { beginAtZero: true }
                }
            }
        });
    })
    .catch(error => {
        console.error('Error fetching admin stats:', error);
        document.getElementById('adminCount').textContent = 'Error';
        document.getElementById('merchantCount').textContent = 'Error';
        document.getElementById('userCount').textContent = 'Error';
        document.getElementById('vaccinationRate').textContent = 'Error';
    });
}

function fetchMerchantStock() {
    token = localStorage.getItem("token") || "";
    console.log("Fetching merchant stock with token:", token);

    if (!token) {
        console.warn("Token not loaded yet. Retrying in 300ms...");
        setTimeout(fetchMerchantStock, 300);
        return;
    }

    fetch('/user-inventory', {
        method: 'GET',
        headers: { "Authorization": `Bearer ${token}` },
    })
    .then(response => {
        if (!response.ok) {
            if (response.status === 403 || response.status === 401) {
                console.error('Unauthorized access, token may be invalid');
                const stockChartCanvas = document.getElementById('stockChart');
                if (stockChartCanvas) {
                    stockChartCanvas.parentElement.innerHTML = '<p>❌ Please log in again to view stock data.</p>';
                }
                return;
            }
            throw new Error(`Status: ${response.status}`);
        }
        return response.json();
    })
    .then(data => {
        console.log('Merchant stock received:', data);
        if (data.role !== 'merchant' || !data.items || data.items.length === 0) {
            const stockChartCanvas = document.getElementById('stockChart');
            if (stockChartCanvas) {
                stockChartCanvas.parentElement.innerHTML = '<p>No stock data available.</p>';
            }
            return;
        }

        const itemNames = data.items.map(item => item.name);
        const stockLevels = data.items.map(item => item.stock);

        const stockChartCanvas = document.getElementById('stockChart');
        if (stockChartCanvas && stockChartCanvas.chart) {
            stockChartCanvas.chart.destroy();
        }

        const ctx = stockChartCanvas.getContext('2d');
        stockChartCanvas.chart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: itemNames,
                datasets: [{
                    label: 'Stock Levels',
                    data: stockLevels,
                    backgroundColor: '#10b981'
                }]
            },
            options: {
                scales: {
                    y: { beginAtZero: true }
                }
            }
        });
    })
    .catch(error => {
        console.error('Error fetching merchant stock:', error);
        const stockChartCanvas = document.getElementById('stockChart');
        if (stockChartCanvas) {
            stockChartCanvas.parentElement.innerHTML = '<p>❌ Error loading stock data: ' + error.message + '</p>';
        }
    });
}

function fetchUserProfileData() {
    const profileDisplay = document.getElementById("userProfileDisplay");

    fetch("/user-inventory", {
        method: "GET",
        headers: { "Authorization": `Bearer ${token}` },
    })
    .then(response => {
        if (!response.ok) throw new Error("Failed to fetch profile");
        return response.json();
    })
    .then(data => {
        const name = `${data.first_name || 'N/A'} ${data.last_name || 'N/A'}`;
        const email = data.email || 'N/A';
        const prsId = data.prs_id || 'N/A';
        const userId = data.user_id || 'N/A';
        const dob = data.dob || 'N/A';
        const status = data.status || 'N/A';
        const vaccination = data.vaccination ? `${data.vaccination.status} (${data.vaccination.vaccine_type} on ${data.vaccination.date})` : 'Not vaccinated';

        profileDisplay.innerText = `
Name: ${name}
Email: ${email}
PRS ID: ${prsId}
User ID: ${userId}
Date of Birth: ${dob}
Status: ${status}
Vaccination: ${vaccination}
        `;
    })
    .catch(err => {
        console.error("Error fetching profile:", err);
        profileDisplay.innerText = "❌ Error loading profile.";
    });
}

function toggleUserStatus() {
    const email = document.getElementById('toggleEmail').value;
    const deleteResponse = document.getElementById('deleteResponse');

    fetch('/admin/toggle-user-status', {
        method: 'POST',
        headers: {
            "Content-Type": "application/json",
            "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ email }),
    })
    .then(response => {
        if (!response.ok) {
            if (response.status === 403 || response.status === 401) {
                window.location.href = '/login';
                return;
            }
            return response.json().then(errorData => {
                throw new Error(errorData.message || `Status: ${response.status}`);
            });
        }
        return response.json();
    })
    .then(data => {
        deleteResponse.textContent = `✅ ${data.message}`;
        listUsers(); // Refresh the user list after toggling status
    })
    .catch(error => {
        deleteResponse.textContent = `❌ ${error.message}`;
    });
}

function searchUsers() {
    const query = document.getElementById('searchUser').value.trim();
    const listResponse = document.getElementById('listResponse');

    // Clear any existing timeout
    if (searchTimeout) {
        clearTimeout(searchTimeout);
    }

    // If the query is empty, show the full user list
    if (!query) {
        listUsers();
        return;
    }

    // Debounce the search to avoid excessive API calls
    searchTimeout = setTimeout(() => {
        fetch('/admin/search-users', {
            method: 'POST',
            headers: {
                "Content-Type": "application/json",
                "Authorization": `Bearer ${token}`,
            },
            body: JSON.stringify({ query }),
        })
        .then(response => {
            if (!response.ok) {
                if (response.status === 403 || response.status === 401) {
                    window.location.href = '/login';
                    return;
                }
                return response.json().then(errorData => {
                    throw new Error(errorData.message || `Status: ${response.status}`);
                });
            }
            return response.json();
        })
        .then(users => {
            if (users.length === 0) {
                listResponse.innerHTML = "<p>No users found.</p>";
                return;
            }
            listResponse.innerHTML = "<h3>Search Results:</h3><ul>" + 
                users.map(user => {
                    const name = (user.first_name || user.last_name) 
                        ? `${user.first_name || ''} ${user.last_name || ''}`.trim() 
                        : "No Name";
                    return `<li>
                        <span class="user-info">${name} - ${user.email}</span>
                        <button class="details-btn" onclick='showUserDetails(${JSON.stringify(user)})'>Details</button>
                    </li>`;
                }).join("") + 
                "</ul>";
        })
        .catch(error => {
            listResponse.innerHTML = `<p>❌ ${error.message}</p>`;
        });
    }, 300); // 300ms debounce delay
}

function requestVaccination() {
    if (!token) {
        console.error("No token found, redirecting to login");
        window.location.href = '/login';
        return;
    }

    const vaccineType = document.getElementById('vaccineType').value.trim();
    const pdfUploadResponse = document.getElementById('pdfUploadResponse');

    if (!vaccineType) {
        pdfUploadResponse.innerText = "❌ Please provide a vaccine type.";
        return;
    }

    fetch('/request-vaccination', {
        method: 'POST',
        headers: {
            "Content-Type": "application/json",
            "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ vaccine_type: vaccineType }),
    })
    .then(response => {
        if (!response.ok) {
            if (response.status === 401 || response.status === 403) {
                return response.json().then(errorData => {
                    if (response.status === 403 && errorData.message.includes('maximum of 3 pending')) {
                        throw new Error(errorData.message);
                    }
                    console.error("Unauthorized, redirecting to login");
                    window.location.href = '/login';
                });
            }
            return response.json().then(errorData => {
                throw new Error(errorData.message || `Status: ${response.status}`);
            });
        }
        return response.json();
    })
    .then(data => {
        pdfUploadResponse.innerText = `✅ ${data.message}`;
        fetchVaccinationRequestStatus(); // Refresh status table
    })
    .catch(error => {
        pdfUploadResponse.innerText = `❌ ${error.message}`;
    });
}

function resetUI() {
    const currentPath = window.location.pathname;
    const logoutButton = document.getElementById("logoutButton");
    const inventoryDisplay = document.getElementById("inventoryDisplay");
    const inventoryTitle = document.getElementById("inventoryTitle");
    const totalValueDisplay = document.getElementById("totalValue");
    const vaccinationDisplay = document.getElementById("vaccinationDisplay");
    const prsIdDisplay = document.getElementById("prsIdDisplay");
    const pdfUploadResponse = document.getElementById("pdfUploadResponse");
    const itemSearchResponse = document.getElementById("itemSearchResponse");
    const responseDisplay = document.getElementById("response");
    const createResponse = document.getElementById("createResponse");
    const deleteResponse = document.getElementById("deleteResponse");
    const listResponse = document.getElementById("listResponse");
    const vaccinationResponse = document.getElementById("vaccinationResponse");
    const vaccinationRequestStatus = document.getElementById("vaccinationRequestStatus");
    const stockListResponse = document.getElementById("stockListResponse");
    const adminCount = document.getElementById("adminCount");
    const merchantCount = document.getElementById("merchantCount");
    const userCount = document.getElementById("userCount");
    const vaccinationRate = document.getElementById("vaccinationRate");
    const stockChartCanvas = document.getElementById("stockChart");
    const statsChartCanvas = document.getElementById("statsChart");

    if (logoutButton) logoutButton.style.display = token ? "block" : "none";
    if (inventoryDisplay) inventoryDisplay.innerText = "No inventory data.";
    if (inventoryTitle) inventoryTitle.innerText = "Your Inventory";
    if (totalValueDisplay) totalValueDisplay.innerText = "$0.00";
    if (vaccinationDisplay) vaccinationDisplay.innerText = "No records available.";
    if (prsIdDisplay) prsIdDisplay.innerText = "";
    if (pdfUploadResponse) pdfUploadResponse.innerText = "";
    if (itemSearchResponse) itemSearchResponse.innerText = "";
    if (responseDisplay) responseDisplay.innerText = "";
    if (createResponse) createResponse.innerText = "";
    if (deleteResponse) deleteResponse.innerText = "";
    if (listResponse) listResponse.innerHTML = "<p>Loading users...</p>";
    if (vaccinationResponse) vaccinationResponse.innerText = "";
    if (vaccinationRequestStatus) vaccinationRequestStatus.innerHTML = "<p>Loading vaccination request status...</p>";
    if (stockListResponse) stockListResponse.innerText = "";
    if (adminCount) adminCount.textContent = "Loading...";
    if (merchantCount) merchantCount.textContent = "Loading...";
    if (userCount) userCount.textContent = "Loading...";
    if (vaccinationRate) vaccinationRate.textContent = "Loading...";
    if (stockChartCanvas && stockChartCanvas.chart) {
        stockChartCanvas.chart.destroy();
        stockChartCanvas.parentElement.innerHTML = '<canvas id="stockChart"></canvas>';
    }
    if (statsChartCanvas && statsChartCanvas.chart) {
        statsChartCanvas.chart.destroy();
        statsChartCanvas.parentElement.innerHTML = '<canvas id="statsChart"></canvas>';
    }
    if (currentPath === "/public") {
        fetchInventory();
        fetchVaccinationRequestStatus();
        fetchUserProfileData();
    }
    if (currentPath === "/public" || currentPath === "/merchant") {
        fetchInventory();
    }
    if (currentPath === "/admin") {
        fetchAdminStats();
        listUsers();
        listVaccinationRequests();
        listStocks();
    }    
}

function listVaccinationRequests() {
    const vaccinationRequestsList = document.getElementById("vaccinationRequestsList");
    fetch("/admin/list-vaccination-requests", {
        method: "GET",
        headers: { "Authorization": `Bearer ${token}` },
    })
        .then(response => {
            if (!response.ok) {
                if (response.status === 403 || response.status === 401) {
                    window.location.href = "/login";
                    return;
                }
                return response.json().then(errorData => {
                    throw new Error(errorData.message || `Status: ${response.status}`);
                });
            }
            return response.json();
        })
        .then(requests => {
            if (requests.length === 0) {
                vaccinationRequestsList.innerHTML = "<p>No pending vaccination requests.</p>";
                return;
            }
            vaccinationRequestsList.innerHTML = "<h3>Pending Vaccination Requests:</h3><ul>" +
                requests.map(req => `
                    <li>
                        <span class="user-info">User ID: ${req.user_id} - Vaccine: ${req.vaccine_type} (Requested on: ${req.date})</span>
                        <div class="form-group">
                            <label for="adminResponse-${req.request_id}">Response Note</label>
                            <input id="adminResponse-${req.request_id}" class="form-control" placeholder="Optional note">
                        </div>
                        <button class="btn btn-success" onclick='approveVaccination("${req.request_id}")'>Approve</button>
                        <button class="btn btn-danger" onclick='rejectVaccination("${req.request_id}")'>Reject</button>
                    </li>
                `).join("") +
                "</ul>";
        })
        .catch(error => {
            vaccinationRequestsList.innerHTML = `<p>❌ ${error.message}</p>`;
        });
}

function approveVaccination(requestId) {
    const adminResponse = document.getElementById(`adminResponse-${requestId}`).value.trim();
    const vaccinationRequestsList = document.getElementById("vaccinationRequestsList");

    fetch("/admin/approve-vaccination", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ request_id: requestId, admin_response: adminResponse }),
    })
        .then(response => {
            if (!response.ok) {
                if (response.status === 403 || response.status === 401) {
                    window.location.href = "/login";
                    return;
                }
                return response.json().then(errorData => {
                    throw new Error(errorData.message || `Status: ${response.status}`);
                });
            }
            return response.json();
        })
        .then(data => {
            vaccinationRequestsList.innerHTML = `<p>✅ ${data.message}</p>`;
            listVaccinationRequests(); // Refresh the list
        })
        .catch(error => {
            vaccinationRequestsList.innerHTML = `<p>❌ ${error.message}</p>`;
        });
}

function fetchAuditLogs() {
    const logContainer = document.getElementById('auditLogsContainer');
    logContainer.innerHTML = '<p>Loading audit logs...</p>';
    fetch('/admin/audit-logs', {
        headers: {
            'Authorization': `Bearer ${token}`
        }
    })
    .then(response => {
        if (!response.ok) {
            if (response.status === 401 || response.status === 403) {
                window.location.href = '/login';
                return;
            }
            throw new Error(`Failed to fetch audit logs: ${response.status}`);
        }
        return response.json();
    })
    .then(data => {
        logContainer.innerHTML = '';
        if (!data.logs || data.logs.length === 0) {
            logContainer.innerHTML = '<p>No audit logs found.</p>';
            return;
        }
        let html = '<ul class="audit-log-list">';
        data.logs.forEach(log => {
            html += `
                <li>
                    <span class="log-info">[${log.timestamp}] ${log.action} by ${log.user_id || 'System'} - ${log.details || 'No details'}</span>
                </li>
            `;
        });
        html += '</ul>';
        logContainer.innerHTML = html;
    })
    .catch(error => {
        console.error('Error fetching audit logs:', error.message);
        logContainer.innerHTML = `<p>❌ ${error.message}</p>`;
    });
}

function rejectVaccination(requestId) {
    const adminResponse = document.getElementById(`adminResponse-${requestId}`).value.trim();
    const vaccinationRequestsList = document.getElementById("vaccinationRequestsList");

    fetch("/admin/reject-vaccination", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ request_id: requestId, admin_response: adminResponse }),
    })
        .then(response => {
            if (!response.ok) {
                if (response.status === 403 || response.status === 401) {
                    window.location.href = "/login";
                    return;
                }
                return response.json().then(errorData => {
                    throw new Error(errorData.message || `Status: ${response.status}`);
                });
            }
            return response.json();
        })
        .then(data => {
            vaccinationRequestsList.innerHTML = `<p>✅ ${data.message}</p>`;
            listVaccinationRequests(); // Refresh the list
        })
        .catch(error => {
            vaccinationRequestsList.innerHTML = `<p>❌ ${error.message}</p>`;
        });
}

document.addEventListener('DOMContentLoaded', () => {
    const loginForm = document.getElementById("loginForm");
    if (loginForm) {
        loginForm.addEventListener("submit", login);
    }
    const searchStockInput = document.getElementById('searchStock');
    if (searchStockInput) {
        searchStockInput.addEventListener('input', searchStocks);
    }

    const vaccinationRequestForm = document.getElementById('vaccinationRequestForm');
    if (vaccinationRequestForm) {
        vaccinationRequestForm.addEventListener('submit', (e) => {
            e.preventDefault();
            requestVaccination();
        });
    }

    const pdfUploadForm = document.getElementById('pdfUploadForm');
    if (pdfUploadForm) {
        pdfUploadForm.addEventListener('submit', (e) => {
            e.preventDefault();
            uploadVaccinationPdf();
        });
    }

    const navLinks = document.querySelectorAll('.sidebar a');
    const cards = document.querySelectorAll('.card');
    const pageTitle = document.getElementById('page-title');

    if (pageTitle) {
        function showCard(sectionId) {
            if (!sectionId) {
                console.error('sectionId is undefined, defaulting to dashboard-card');
                sectionId = 'dashboard-card'; // Fallback to default section
            }
        
            cards.forEach(card => card.classList.remove('active'));
            const targetCard = document.getElementById(sectionId);
            if (targetCard) {
                targetCard.classList.add('active');
            } else {
                console.warn(`No card found for sectionId: ${sectionId}`);
            }
        
            navLinks.forEach(link => link.classList.remove('active'));
            const activeLink = document.querySelector(`.sidebar a[data-section="${sectionId}"]`);
            if (activeLink) {
                activeLink.classList.add('active');
            }
        
            pageTitle.textContent = "Dashboard";
        
            if (sectionId === 'dashboard-card') {
                fetchMerchantStock();
            }
            if (sectionId === 'sales-card') {
                fetchMerchantSales();
            }
        }
        

        navLinks.forEach(link => {
            link.addEventListener('click', (e) => {
                e.preventDefault();
                const sectionId = link.getAttribute('data-section');
                console.log('Nav link clicked:', link, 'sectionId:', sectionId);
                showCard(sectionId);
            });
        });

        showCard('dashboard-card');
    }

    // Modal close functionality
    const modals = document.querySelectorAll('.modal');
    modals.forEach(modal => {
        modal.addEventListener('click', (e) => {
            if (e.target === modal || e.target.classList.contains('modal-close')) {
                modal.style.display = 'none';
            }
        });
    });
});

let allItems = [];

async function fetchAllItems() {
  try {
    const response = await fetch("/admin/list-stocks", {
      headers: {
        Authorization: `Bearer ${localStorage.getItem("token")}`,
      },
    });
    const data = await response.json();
    allItems = [];

    data.forEach((merchant) => {
      if (merchant.items) {
        merchant.items.forEach((item) => {
          allItems.push({
            name: item.name,
            stock: item.stock,
            price: item.price || 0,
            merchant_id: merchant.merchant_id,
            limit: item.limit || null
          });
        });
      }
    });

    displayItemList(allItems);
  } catch (error) {
    console.error("Error fetching items:", error);
  }
}

function displayItemList(items) {
    const itemList = document.getElementById("itemList");
    itemList.innerHTML = "";

    if (items.length === 0) {
        itemList.innerHTML = "<li>No items found.</li>";
        return;
    }

    items.forEach((item) => {
        if (!item.name || item.stock === undefined) return;

        const li = document.createElement("li");

        let priceText = item.price !== undefined && item.price !== null ? `$${item.price.toFixed(2)}` : '$0.00';
        let stockText = item.stock > 0 ? `Stock: ${item.stock}` : `<span style="color: red;">Out of Stock</span>`;

        let buyButton = item.stock > 0 ? 
            `<button class="btn btn-success" onclick='showBuyModal(${JSON.stringify(item)})'>Buy</button>` :
            `<button class="btn btn-secondary" disabled>Out of Stock</button>`;

        li.innerHTML = `
            <span class="user-info">${item.name} | Price: ${priceText} | ${stockText}</span>
            <div>
                ${buyButton}
                <button class="details-btn" onclick='showItemDetails(${JSON.stringify(item)})'>Details</button>
            </div>
        `;
        itemList.appendChild(li);
    });
}



function filterItemList() {
const query = document.getElementById("itemSearch").value.toLowerCase();
const filtered = allItems.filter((item) =>
    item.name.toLowerCase().includes(query)
);
displayItemList(filtered);
}

function showItemDetails(item) {
document.getElementById("modalItemName").innerText = item.name;
document.getElementById("modalItemStock").innerText = item.stock;
document.getElementById("modalMerchantId").innerText = item.merchant_id;
document.getElementById("itemDetailsModal").style.display = "block";
}

function closeItemModal() {
document.getElementById("itemDetailsModal").style.display = "none";
}

function showBuyModal(item) {
    selectedBuyItem = item;
    document.getElementById("buyModalItemName").innerText = item.name;

    // Πρώτα έλεγχος ημέρας
    fetch(`/can-purchase-today/${encodeURIComponent(item.name)}`, {
        headers: { Authorization: `Bearer ${token}` }
    })
    .then(res => res.json())
    .then(dayData => {
        if (!dayData.can_purchase) {
            document.getElementById("allowedQty").innerText = "0";
            document.getElementById("purchaseQty").disabled = true;
            document.getElementById("purchaseQty").value = "";
            document.getElementById("buyErrorMessage").innerText = dayData.message || "You are not eligible to purchase this item at this time.";
            document.getElementById("completeOrderBtn").disabled = true;
            document.getElementById("buyModal").style.display = "block";
            return;
        }

        fetch(`/allowed-purchase/${encodeURIComponent(item.name)}`, {
            headers: { Authorization: `Bearer ${token}` }
        })
        .then(res => res.json())
        .then(data => {
            let allowed = data.allowed !== null ? data.allowed : (item.limit !== null ? item.limit : item.stock || 0);

            if (allowed <= 0) {
                document.getElementById("allowedQty").innerText = "0";
                document.getElementById("purchaseQty").disabled = true;
                document.getElementById("purchaseQty").value = "";
                document.getElementById("buyErrorMessage").innerText = "No available quantity for purchase.";
                document.getElementById("completeOrderBtn").disabled = true;
            } else {
                document.getElementById("allowedQty").innerText = allowed;
                document.getElementById("purchaseQty").disabled = false;
                document.getElementById("purchaseQty").max = allowed;
                document.getElementById("purchaseQty").value = "";
                document.getElementById("buyErrorMessage").innerText = "";
                document.getElementById("completeOrderBtn").disabled = true;
            }

            selectedBuyItem.allowed = allowed;
            document.getElementById("buyModal").style.display = "block";
        });
    });
}



function validatePurchaseQty() {
    const qtyInput = document.getElementById("purchaseQty");
    const errorMsg = document.getElementById("buyErrorMessage");
    const completeBtn = document.getElementById("completeOrderBtn");

    const value = qtyInput.value.trim();

    if (!/^\d+$/.test(value)) {
        errorMsg.innerText = "Only whole numbers are allowed.";
        completeBtn.disabled = true;
        return;
    }

    const qty = parseInt(value, 10);
    if (qty < 1 || qty > selectedBuyItem.allowed) {
        errorMsg.innerText = `Quantity must be between 1 and ${selectedBuyItem.allowed}.`;
        completeBtn.disabled = true;
    } else {
        errorMsg.innerText = "";
        completeBtn.disabled = false;
    }
}


function completeOrder() {
    const qty = parseInt(document.getElementById("purchaseQty").value, 10);

    if (!qty || qty < 1) {
        alert("Please enter a valid quantity.");
        return;
    }

    fetch("/purchase-item", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "Authorization": `Bearer ${token}`
        },
        body: JSON.stringify({
            item_name: selectedBuyItem.name,
            quantity: qty
        })
    })
    .then(res => res.json().then(body => ({ ok: res.ok, body })))
    .then(({ ok, body }) => {
        if (!ok) throw new Error(body.message);

        alert(`✅ ${body.message}`);
        document.getElementById("buyModal").style.display = "none";
    })
    .catch(err => {
        alert(`❌ ${err.message}`);
    });
}

function fetchMerchantSales() {
    fetch('/merchant-sales', {
        headers: { Authorization: `Bearer ${token}` }
    })
    .then(res => res.json())
    .then(data => {
        const tbody = document.getElementById('salesTableBody');
        tbody.innerHTML = "";

        if (data.sales.length === 0) {
            tbody.innerHTML = "<tr><td colspan='5'>No sales found.</td></tr>";
            return;
        }

        data.sales.forEach(s => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${s.item_name}</td>
                <td>${s.quantity}</td>
                <td>${s.date}</td>
                <td>${s.buyer_name}</td>
                <td><button class="btn btn-primary" onclick="downloadReceipt('${s.item_name}', ${s.quantity})">Download Receipt</button></td>
            `;
            tbody.appendChild(row);
        });
    })
    .catch(err => {
        console.error("Failed to fetch sales:", err);
    });
}

function fetchTransactions() {
    fetch('/user-purchases', {
        headers: { Authorization: `Bearer ${token}` }
    })
    .then(res => res.json())
    .then(data => {
        const tbody = document.getElementById('transactionsTableBody');
        tbody.innerHTML = "";

        if (data.purchases.length === 0) {
            tbody.innerHTML = "<tr><td colspan='4'>No transactions found.</td></tr>";
            return;
        }

        data.purchases.forEach(p => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${p.item_name}</td>
                <td>${p.quantity}</td>
                <td>${p.date}</td>
                <td><button class="btn btn-primary" onclick="downloadReceipt('${p.item_name}', ${p.quantity})">Download Receipt</button></td>
            `;
            tbody.appendChild(row);
        });
    })
    .catch(err => {
        console.error("Failed to fetch transactions:", err);
    });
}

function downloadReceipt(itemName, quantity) {
    fetch(`/generate-receipt/${encodeURIComponent(itemName)}/${quantity}`, {
        headers: { 'Authorization': `Bearer ${token}` }
    })
    .then(response => {
        if (!response.ok) throw new Error("Failed to generate receipt");
        return response.blob();
    })
    .then(blob => {
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `receipt_${itemName}_${quantity}.pdf`;
        document.body.appendChild(a);
        a.click();
        a.remove();
        window.URL.revokeObjectURL(url);
    })
    .catch(err => {
        alert("Failed to download receipt: " + err.message);
    });
}
