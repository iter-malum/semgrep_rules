using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;

namespace TestControllers
{
    // ---------- True Positive (rule should trigger) ----------

    // TP1: Метод POST без атрибута валидации
    public class AccountController : Controller
    {
        // ruleid: csharp_csrf_rule-ValidateAntiForgeryToken
        [HttpPost]
        public IActionResult UpdateEmail(string email)
        {
            // Обновление email пользователя
            return Ok();
        }
    }

    // TP2: Метод PUT без атрибута валидации
    public class DataController : Controller
    {
        // ruleid: csharp_csrf_rule-ValidateAntiForgeryToken
        [HttpPut]
        public IActionResult UpdateUserData(int id, string data)
        {
            // Обновление данных
            return Ok();
        }
    }

    // TP3: Метод DELETE без атрибута валидации
    public class AdminController : Controller
    {
        // ruleid: csharp_csrf_rule-ValidateAntiForgeryToken
        [HttpDelete]
        public IActionResult DeleteUser(int id)
        {
            // Удаление пользователя
            return Ok();
        }
    }

    // TP4: Метод POST с другими атрибутами, но без ValidateAntiForgeryToken
    public class SettingsController : Controller
    {
        // ruleid: csharp_csrf_rule-ValidateAntiForgeryToken
        [HttpPost]
        [Authorize(Roles = "Admin")]
        public IActionResult ChangePassword(string newPassword)
        {
            // Смена пароля - критическая операция
            return Ok();
        }
    }

    // TP5: Контроллер имеет атрибут, но метод переопределяет без валидации
    [ValidateAntiForgeryToken]
    public class SecureController : Controller
    {
        // ruleid: csharp_csrf_rule-ValidateAntiForgeryToken
        [HttpPost]
        public IActionResult UpdateProfile(string name)
        {
            // Должен наследовать атрибут от контроллера, но не переопределяет
            return Ok();
        }
    }

    // TP6: Метод POST с атрибутом IgnoreAntiforgeryToken (опасно)
    public class DangerousController : Controller
    {
        [HttpPost]
        [IgnoreAntiforgeryToken]
        // ruleid: csharp_csrf_rule-ValidateAntiForgeryToken
        public IActionResult TransferMoney(string toAccount, decimal amount)
        {
            // Игнорирует анти-CSRF защиту
            return Ok();
        }
    }

    // TP7: Метод POST без атрибута, но с сложными параметрами
    public class ApiController : Controller
    {
        // ruleid: csharp_csrf_rule-ValidateAntiForgeryToken
        [HttpPost]
        public IActionResult CreateOrder([FromBody] OrderRequest request)
        {
            // Создание заказа
            return Ok();
        }
    }

    // TP8: Метод POST с переопределением маршрута
    public class ProductController : Controller
    {
        // ruleid: csharp_csrf_rule-ValidateAntiForgeryToken
        [HttpPost]
        [Route("api/products/update")]
        public IActionResult UpdateProductStock(int productId, int quantity)
        {
            // Обновление остатков
            return Ok();
        }
    }

    // TP9: Асинхронный метод POST без валидации
    public class AsyncController : Controller
    {
        // ruleid: csharp_csrf_rule-ValidateAntiForgeryToken
        [HttpPost]
        public async Task<IActionResult> ProcessPaymentAsync(PaymentInfo payment)
        {
            // Платежная операция
            await Task.Delay(100);
            return Ok();
        }
    }

    // TP10: Контроллер без глобальной защиты и метод без атрибута
    public class InsecureController : ControllerBase
    {
        // ruleid: csharp_csrf_rule-ValidateAntiForgeryToken
        [HttpPost]
        public IActionResult UpdateSettings(UserSettings settings)
        {
            // Изменение настроек
            return Ok();
        }
    }

    // ---------- False Positive (rule should NOT trigger) ----------

    // FP1: Метод GET (не изменяет состояние)
    public class ReadController : Controller
    {
        [HttpGet]
        // ok: csharp_csrf_rule-ValidateAntiForgeryToken
        public IActionResult GetUserData(int id)
        {
            return Ok();
        }
    }

    // FP2: Метод POST с атрибутом валидации
    public class SecureAccountController : Controller
    {
        [HttpPost]
        [ValidateAntiForgeryToken]
        // ok: csharp_csrf_rule-ValidateAntiForgeryToken
        public IActionResult UpdateEmail(string email)
        {
            return Ok();
        }
    }

    // FP3: Контроллер с глобальной валидацией и метод без атрибута (наследует)
    [ValidateAntiForgeryToken]
    public class GloballySecuredController : Controller
    {
        [HttpPost]
        // ok: csharp_csrf_rule-ValidateAntiForgeryToken
        public IActionResult UpdateData(string data)
        {
            // Наследует атрибут от контроллера
            return Ok();
        }
    }

    // FP4: Метод PUT с атрибутом валидации
    public class SecureDataController : Controller
    {
        [HttpPut]
        [ValidateAntiForgeryToken]
        // ok: csharp_csrf_rule-ValidateAntiForgeryToken
        public IActionResult UpdateUserData(int id, string data)
        {
            return Ok();
        }
    }

    // FP5: Метод DELETE с атрибутом валидации
    public class SecureAdminController : Controller
    {
        [HttpDelete]
        [ValidateAntiForgeryToken]
        // ok: csharp_csrf_rule-ValidateAntiForgeryToken
        public IActionResult DeleteUser(int id)
        {
            return Ok();
        }
    }

    // FP6: Контроллер с AutoValidateAntiforgeryToken (глобальная защита)
    [AutoValidateAntiforgeryToken]
    public class AutoSecuredController : Controller
    {
        [HttpPost]
        // ok: csharp_csrf_rule-ValidateAntiForgeryToken
        public IActionResult UpdateProfile(string profile)
        {
            // Глобальная защита через AutoValidateAntiforgeryToken
            return Ok();
        }
    }

    // FP7: Метод с атрибутом валидации и другими атрибутами
    public class MixedController : Controller
    {
        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize]
        // ok: csharp_csrf_rule-ValidateAntiForgeryToken
        public IActionResult ChangePassword(string password)
        {
            return Ok();
        }
    }

    // FP8: Web API с атрибутом валидации (хотя для API часто используют другие методы)
    [ApiController]
    [Route("api/[controller]")]
    public class SecureApiController : ControllerBase
    {
        [HttpPost]
        [ValidateAntiForgeryToken]
        // ok: csharp_csrf_rule-ValidateAntiForgeryToken
        public IActionResult CreateResource(Resource resource)
        {
            return Ok();
        }
    }

    // FP9: Метод с IgnoreAntiforgeryToken НЕ должен считаться FP, если он в глобально защищенном контроллере
    // Это все еще уязвимо! Так что это TP, а не FP
    [AutoValidateAntiforgeryToken]
    public class MixedSecurityController : Controller
    {
        // ruleid: csharp_csrf_rule-ValidateAntiForgeryToken
        [HttpPost]
        [IgnoreAntiforgeryToken]
        public IActionResult DangerousEndpoint(string data)
        {
            // IgnoreAntiforgeryToken отключает даже глобальную защиту
            return Ok();
        }
    }

    // FP10: Метод POST с ValidateAntiForgeryToken через отдельный атрибут
    public class ExplicitController : Controller
    {
        [HttpPost]
        [ServiceFilter(typeof(AntiforgeryFilter))]
        // ok: csharp_csrf_rule-ValidateAntiForgeryToken
        public IActionResult ProcessData(DataModel model)
        {
            return Ok();
        }
    }

    // FP11: Метод, который не изменяет состояние (пост но идемпотентный)
    public class SearchController : Controller
    {
        [HttpPost]
        // ok: csharp_csrf_rule-ValidateAntiForgeryToken
        public IActionResult Search(string query)
        {
            // POST используется для сложного поиска, но не изменяет данные
            return Ok();
        }
    }

    // FP12: PATCH метод с валидацией
    public class SecurePatchController : Controller
    {
        [HttpPatch]
        [ValidateAntiForgeryToken]
        // ok: csharp_csrf_rule-ValidateAntiForgeryToken
        public IActionResult PartialUpdate(int id, PatchData data)
        {
            return Ok();
        }
    }
}

// Модели для тестов
public class OrderRequest
{
    public string ProductId { get; set; }
    public int Quantity { get; set; }
}

public class PaymentInfo
{
    public string CardNumber { get; set; }
    public decimal Amount { get; set; }
}

public class UserSettings
{
    public string Theme { get; set; }
    public bool Notifications { get; set; }
}

public class Resource
{
    public string Name { get; set; }
    public string Value { get; set; }
}

public class DataModel
{
    public string Data { get; set; }
}

public class PatchData
{
    public string Field { get; set; }
    public object Value { get; set; }
}